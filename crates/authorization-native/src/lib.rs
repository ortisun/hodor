//! Conditions of the native engine in Common Expression Language.
//!
//! `CelConditionLanguage` implements the authorization context's
//! `ConditionLanguage` port over the `cel` crate. What the interpreter does
//! not check, this crate checks when a condition is published: the
//! variables, the absence of message literals, the size and the nesting of
//! comprehensions. Every run is bounded by an iteration budget and a
//! deadline. The moment is RFC 3339 text in UTC, to the second. See `docs/architecture/contexts/authorization.md`,
//! "Conditions", and Decision 0025.

use cel::common::ast::{EntryExpr, Expr, IdedExpr};
use cel::{Context, Deadline, Env, Program, RuntimeOptions, Value};
use hodor_authorization::api::{
    CompiledCondition, Condition, ConditionInput, ConditionLanguage, condition_failed,
    condition_invalid, condition_too_costly,
};
use hodor_kernel::{DomainError, Timestamp};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The variables a condition may read.
pub const VARIABLES: [&str; 4] = ["subject", "resource", "action", "context"];

/// The most nodes a condition's expression may have.
pub const MAX_NODES: usize = 256;

/// How deep comprehensions (`all`, `exists`, `exists_one`, `map`, `filter`)
/// may be nested.
pub const MAX_COMPREHENSION_DEPTH: usize = 2;

/// The most iterations one run may make, across all its comprehensions.
pub const MAX_ITERATIONS: u64 = 1000;

/// Conditions in Common Expression Language, with the standard functions
/// and macros and nothing of Hodor's own.
#[derive(Clone)]
pub struct CelConditionLanguage {
    env: Arc<Env>,
}

impl std::fmt::Debug for CelConditionLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CelConditionLanguage")
            .finish_non_exhaustive()
    }
}

impl Default for CelConditionLanguage {
    fn default() -> Self {
        Self::new()
    }
}

impl CelConditionLanguage {
    /// The language with its bounds.
    #[must_use]
    pub fn new() -> Self {
        let mut env = Env::stdlib();
        env.set_options(RuntimeOptions::default().with_max_iterations(MAX_ITERATIONS));
        Self { env: Arc::new(env) }
    }
}

/// The size of an expression and how deep its comprehensions nest, or why
/// it cannot be used.
#[derive(Debug, Default)]
struct Shape {
    nodes: usize,
    deepest: usize,
    message_literal: bool,
}

fn measure(expression: &IdedExpr, depth: usize, shape: &mut Shape) {
    shape.nodes += 1;
    if shape.nodes > MAX_NODES {
        return;
    }
    match &expression.expr {
        Expr::Unspecified | Expr::Ident(_) | Expr::Literal(_) => {}
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                measure(target, depth, shape);
            }
            for argument in &call.args {
                measure(argument, depth, shape);
            }
        }
        Expr::Comprehension(comprehension) => {
            let inside = depth + 1;
            shape.deepest = shape.deepest.max(inside);
            measure(&comprehension.iter_range, depth, shape);
            measure(&comprehension.accu_init, depth, shape);
            measure(&comprehension.loop_cond, inside, shape);
            measure(&comprehension.loop_step, inside, shape);
            measure(&comprehension.result, depth, shape);
        }
        Expr::List(list) => {
            for element in &list.elements {
                measure(element, depth, shape);
            }
        }
        Expr::Map(map) => {
            for entry in &map.entries {
                if let EntryExpr::MapEntry(entry) = &entry.expr {
                    measure(&entry.key, depth, shape);
                    measure(&entry.value, depth, shape);
                }
            }
        }
        Expr::Select(select) => measure(&select.operand, depth, shape),
        Expr::Struct(_) => shape.message_literal = true,
    }
}

impl ConditionLanguage for CelConditionLanguage {
    fn compile(&self, condition: &Condition) -> Result<Arc<dyn CompiledCondition>, DomainError> {
        let program = self.env.compile(condition.as_str()).map_err(|errors| {
            let message = errors.to_string();
            let first = message.lines().next().unwrap_or("it does not parse");
            condition_invalid(first)
        })?;
        let mut shape = Shape::default();
        measure(program.expression(), 0, &mut shape);
        if shape.message_literal {
            return Err(condition_invalid("a condition writes no message literal"));
        }
        if shape.nodes > MAX_NODES {
            return Err(condition_too_costly("more than 256 nodes"));
        }
        if shape.deepest > MAX_COMPREHENSION_DEPTH {
            return Err(condition_too_costly(
                "comprehensions nested more than two deep",
            ));
        }
        let references = program.references();
        if let Some(stray) = references
            .variables()
            .into_iter()
            .find(|name| !VARIABLES.contains(name))
        {
            return Err(condition_invalid(&format!(
                "`{stray}` is not one of subject, resource, action and context"
            )));
        }
        // Operators are named with symbols (`_==_`, `@in`, `!_`); a name
        // that starts with a letter is a function, which must be a standard
        // one.
        if let Some(unknown) = references.functions().into_iter().find(|name| {
            name.starts_with(|c: char| c.is_ascii_alphabetic()) && self.env.function(name).is_none()
        }) {
            return Err(condition_invalid(&format!(
                "`{unknown}` is not a standard function"
            )));
        }
        Ok(Arc::new(CelCondition {
            env: Arc::clone(&self.env),
            program,
        }))
    }
}

/// A compiled condition.
struct CelCondition {
    env: Arc<Env>,
    program: Program,
}

fn value(of: &impl serde::Serialize) -> Result<Value, DomainError> {
    cel::to_value(of).map_err(|_| condition_failed("an attribute cannot be read as a value"))
}

/// The moment as RFC 3339 text in UTC, to the second, such as
/// `2024-10-04T00:00:00Z`: every moment has the same shape, so comparing the
/// text compares the moments.
fn moment(at: Timestamp) -> Result<Value, DomainError> {
    let whole = at
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|_| condition_failed("the moment cannot be written"))?;
    let text = whole
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| condition_failed("the moment cannot be written"))?;
    Ok(Value::from(text))
}

impl CompiledCondition for CelCondition {
    fn holds(&self, input: &ConditionInput, time_limit: Duration) -> Result<bool, DomainError> {
        let deadline = Deadline::after(time_limit);
        let mut context = Context::with_env(Arc::clone(&self.env));
        context.set_interrupt(&deadline);
        context.add_variable_from_value("subject", value(&input.subject)?);
        context.add_variable_from_value("resource", value(&input.resource)?);
        context.add_variable_from_value("action", Value::from(input.action.as_str()));
        let moment: HashMap<String, Value> = [
            ("attributes".to_owned(), value(&input.context.attributes)?),
            (
                "application".to_owned(),
                input
                    .context
                    .application
                    .as_deref()
                    .map_or(Value::Null, Value::from),
            ),
            ("time".to_owned(), moment(input.context.time)?),
        ]
        .into();
        context.add_variable_from_value("context", moment);
        match self.program.execute(&context) {
            Ok(Value::Bool(held)) => Ok(held),
            Ok(_) => Err(condition_failed("a condition gives a boolean")),
            Err(error) => Err(condition_failed(&error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_authorization::api::{
        Attributes, ConditionContext, ConditionResource, ConditionSubject,
    };

    fn attributes(values: &[(&str, serde_json::Value)]) -> Attributes {
        Attributes::new(
            values
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        )
        .expect("attributes")
    }

    fn input() -> ConditionInput {
        ConditionInput {
            subject: ConditionSubject {
                kind: "user".to_owned(),
                id: "ana".to_owned(),
                attributes: attributes(&[
                    ("department", serde_json::json!("sales")),
                    ("level", serde_json::json!(3)),
                    ("groups", serde_json::json!(["staff", "sales"])),
                ]),
                asserted: Attributes::none(),
            },
            resource: ConditionResource {
                kind: "document".to_owned(),
                id: Some("d-1".to_owned()),
                attributes: attributes(&[("department", serde_json::json!("sales"))]),
            },
            action: "read".to_owned(),
            context: ConditionContext {
                attributes: attributes(&[("address", serde_json::json!("192.0.2.10"))]),
                application: Some("portal".to_owned()),
                time: Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
            },
        }
    }

    fn compile(text: &str) -> Result<Arc<dyn CompiledCondition>, DomainError> {
        CelConditionLanguage::new().compile(&Condition::parse(text).expect("condition"))
    }

    fn run(text: &str) -> Result<bool, DomainError> {
        compile(text)
            .expect("compiles")
            .holds(&input(), Duration::from_millis(10))
    }

    fn code<T>(result: Result<T, DomainError>) -> Option<String> {
        result.err().map(|error| error.code().to_owned())
    }

    #[test]
    fn a_condition_reads_the_four_variables() {
        assert_eq!(
            run("subject.attributes.department == resource.attributes.department").ok(),
            Some(true)
        );
        assert_eq!(
            run("subject.kind == 'user' && subject.id == 'ana'").ok(),
            Some(true)
        );
        assert_eq!(
            run("resource.kind == 'document' && resource.id == 'd-1'").ok(),
            Some(true)
        );
        assert_eq!(run("action == 'read'").ok(), Some(true));
        assert_eq!(run("action == 'write'").ok(), Some(false));
        assert_eq!(run("context.application == 'portal'").ok(), Some(true));
        assert_eq!(
            run("context.attributes.address.startsWith('192.0.2.')").ok(),
            Some(true)
        );
        assert_eq!(run("subject.attributes.level >= 3").ok(), Some(true));
        assert_eq!(run("'sales' in subject.attributes.groups").ok(), Some(true));
        assert_eq!(run("size(subject.asserted) == 0").ok(), Some(true));
    }

    #[test]
    fn the_moment_is_text_that_compares_as_moments() {
        // 20 000 days after the epoch is 2024-10-04, at midnight.
        assert_eq!(
            run("context.time == '2024-10-04T00:00:00Z'").ok(),
            Some(true)
        );
        assert_eq!(
            run("context.time > '2024-10-03T23:59:59Z'").ok(),
            Some(true)
        );
        assert_eq!(
            run("context.time < '2025-01-01T00:00:00Z'").ok(),
            Some(true)
        );
        assert_eq!(run("context.time.startsWith('2024-')").ok(), Some(true));
        // The time of day, through a regular expression.
        assert_eq!(run("context.time.matches('T(0[0-8]):')").ok(), Some(true));
        assert_eq!(
            run("context.time.matches('T(09|1[0-6]):')").ok(),
            Some(false)
        );
        // Without the chrono feature there is no timestamp type.
        assert_eq!(
            code(compile("context.time < timestamp('2025-01-01T00:00:00Z')")),
            Some("authorization.condition_invalid".to_owned())
        );
    }

    #[test]
    fn a_condition_that_cannot_be_used_is_refused_when_compiled() {
        for text in [
            "subject.id ==",
            "unknown == 1",
            "request.subject == 'ana'",
            "launch('rockets')",
            "hodor.Thing{field: 1}",
        ] {
            assert_eq!(
                code(compile(text)),
                Some("authorization.condition_invalid".to_owned()),
                "{text}"
            );
        }
        // Comprehension variables are not free variables.
        assert!(compile("subject.attributes.groups.exists(g, g == 'staff')").is_ok());
        assert!(compile("has(resource.attributes.department)").is_ok());
    }

    #[test]
    fn a_condition_that_would_cost_too_much_is_refused_when_compiled() {
        let deep = "subject.attributes.groups.all(a, subject.attributes.groups.all(b, \
                    subject.attributes.groups.all(c, a == b && b == c)))";
        assert_eq!(
            code(compile(deep)),
            Some("authorization.condition_too_costly".to_owned())
        );
        let two_deep =
            "subject.attributes.groups.all(a, subject.attributes.groups.exists(b, a == b))";
        assert!(compile(two_deep).is_ok());
        // 200 additions: about 400 nodes in 400 characters.
        let wide = format!("{} > 0", vec!["1"; 200].join("+"));
        assert_eq!(
            code(compile(&wide)),
            Some("authorization.condition_too_costly".to_owned())
        );
    }

    #[test]
    fn a_run_that_fails_never_holds() {
        for text in [
            // An attribute the request does not carry.
            "resource.attributes.owner == subject.id",
            // Not a boolean.
            "subject.attributes.level",
            // An error inside the expression.
            "1 / (subject.attributes.level - 3) > 0",
        ] {
            assert_eq!(
                code(run(text)),
                Some("authorization.condition_failed".to_owned()),
                "{text}"
            );
        }
        // Guarded, the missing attribute is simply false.
        assert_eq!(
            run("has(resource.attributes.owner) && resource.attributes.owner == subject.id").ok(),
            Some(false)
        );
    }

    #[test]
    fn a_run_is_bounded() {
        // Two comprehensions of 40 elements nested: 1640 iterations, more
        // than the budget.
        let list = (0..40).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let text = format!("[{list}].all(a, [{list}].all(b, a >= 0 && b >= 0))");
        assert_eq!(
            code(run(&text)),
            Some("authorization.condition_failed".to_owned())
        );
        // A deadline already passed stops a comprehension at once.
        let compiled = compile("[1, 2, 3].all(a, a > 0)").expect("compiles");
        assert_eq!(
            code(compiled.holds(&input(), Duration::ZERO)),
            Some("authorization.condition_failed".to_owned())
        );
        assert_eq!(
            compiled.holds(&input(), Duration::from_millis(10)).ok(),
            Some(true)
        );
    }

    #[test]
    fn a_compiled_condition_runs_many_times() {
        let compiled = compile("subject.attributes.department == 'sales'").expect("compiles");
        let mut other = input();
        other.subject.attributes = attributes(&[("department", serde_json::json!("legal"))]);
        assert_eq!(
            compiled.holds(&input(), Duration::from_millis(10)).ok(),
            Some(true)
        );
        assert_eq!(
            compiled.holds(&other, Duration::from_millis(10)).ok(),
            Some(false)
        );
        assert_eq!(
            compiled.holds(&input(), Duration::from_millis(10)).ok(),
            Some(true)
        );
    }
}
