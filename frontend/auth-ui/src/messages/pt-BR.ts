// Tudo o que as páginas dizem, em português do Brasil. As mesmas mensagens de `en.ts`.

import type { Messages } from "./en";

export const ptBR: Messages = {
  locale: "pt-BR",
  organization: "Organização",
  loading: "Um momento…",
  working: "Processando…",

  signInTitle: "Entrar",
  identifierLabel: "Endereço de email ou nome de usuário",
  passwordLabel: "Senha",
  showPassword: "Mostrar a senha",
  continue: "Continuar",
  signIn: "Entrar",
  signingInAs: (identifier) => `Entrando como ${identifier}`,
  useAnotherIdentifier: "Usar outro endereço",
  forgotPassword: "Esqueceu a senha?",
  noAccountYet: "Ainda não tem conta?",
  register: "Criar conta",
  rejected: "Não deu certo. Confira o que você digitou e tente de novo.",
  attemptsLeft: (count) =>
    count === 1 ? "Resta mais uma tentativa." : `Restam mais ${count} tentativas.`,
  signInEnded: "Esta entrada foi encerrada.",
  startAgain: "Começar de novo",
  signInExpired: "A entrada demorou demais e foi reiniciada.",
  unknownStep: "Esta página não consegue continuar esta entrada.",

  registerTitle: "Criar uma conta",
  registerLead: "Informe seu endereço de email. Uma mensagem vai levar um link para você terminar.",
  emailLabel: "Endereço de email",
  sendLink: "Enviar o link",
  alreadyRegistered: "Já tem uma conta?",
  checkMailboxTitle: "Confira sua caixa de entrada",
  checkMailbox: (email) =>
    `Se ${email} puder ser usado, uma mensagem está a caminho. Siga o link da mensagem para continuar.`,
  checkMailboxHint: "Nenhuma mensagem depois de alguns minutos? Olhe na pasta de mensagens indesejadas ou peça de novo.",
  askAgain: "Pedir de novo",

  completeRegistrationTitle: "Escolha sua senha",
  displayNameLabel: "Seu nome",
  optional: "opcional",
  newPasswordLabel: "Nova senha",
  newPasswordHint: "Use 12 caracteres ou mais. Uma frase de várias palavras funciona bem.",
  createAccount: "Criar a conta",
  linkInvalidTitle: "Este link não pode ser usado",
  linkInvalid: "O link já foi usado ou expirou.",
  askForNewRegistrationLink: "Pedir um novo link para criar a conta",
  askForNewRecoveryLink: "Pedir um novo link",

  recoverTitle: "Recuperar sua senha",
  recoverLead: "Informe o endereço de email da sua conta. Uma mensagem vai levar um link para você escolher uma nova senha.",
  backToSignIn: "Voltar para a entrada",

  resetPasswordTitle: "Escolha uma nova senha",
  changePassword: "Trocar a senha",

  accountTitle: "Você entrou",
  signedInSince: (moment) => `Conectado desde ${moment}.`,
  signOut: "Sair",

  noticeRegistered: "Sua conta está pronta. Entre para continuar.",
  noticePasswordChanged: "Sua senha foi trocada. Entre com a nova.",
  noticeSignedOut: "Você saiu.",
  noticeProviderRefused: "Não deu certo. Tente de novo ou entre de outra forma.",
  noticeProviderCancelled: "A entrada não foi concluída no provedor.",

  or: "ou",
  continueWith: (provider) => `Continuar com ${provider}`,
  comingBackTitle: "Entrando",

  pageNotFoundTitle: "Página não encontrada",
  pageNotFound: "Não há nada neste endereço.",
  goToSignIn: "Ir para a entrada",

  passwordTooShort: "Esta senha é curta demais.",
  passwordTooLong: "Esta senha é longa demais.",
  passwordIsOwnName: "Não use seu próprio nome ou endereço como senha.",
  passwordReused: "Você já usou esta senha. Escolha outra.",
  displayNameInvalid: "Este nome não pode ser usado.",
  tooManyAttempts: "Tentativas demais.",
  tryAgainInSeconds: (seconds) =>
    seconds === 1 ? "Tente de novo em um segundo." : `Tente de novo em ${seconds} segundos.`,
  tryAgainInMinutes: (minutes) =>
    minutes === 1 ? "Tente de novo em um minuto." : `Tente de novo em ${minutes} minutos.`,
  tryAgainLater: "Tente de novo mais tarde.",
  registrationClosed: "Esta organização não aceita novos cadastros.",
  serverBusy: "O servidor está ocupado. Tente de novo em instantes.",
  unreachable: "Não foi possível falar com o servidor. Confira sua conexão e tente de novo.",
  somethingWentWrong: "Algo deu errado. Tente de novo.",
  requestIdentifier: (identifier) => `Se for relatar o problema, informe ${identifier}.`,
};
