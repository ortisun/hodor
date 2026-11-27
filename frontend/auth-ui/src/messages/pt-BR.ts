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
  totpLabel: "Código do seu aplicativo autenticador",
  totpHint: "Seis dígitos. Eles mudam a cada trinta segundos.",
  useRecoveryCode: "Usar um código de recuperação",
  recoveryCodeLabel: "Código de recuperação",
  recoveryCodeHint: "Um dos códigos que você anotou ou imprimiu. Cada um funciona uma vez.",
  useAuthenticatorApplication: "Usar o código do aplicativo",
  useSecurityKeyInstead: "Usar a chave de segurança",
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
  securityKeyLead: "Use sua chave de segurança, ou a que vem neste dispositivo, para terminar de entrar.",
  useSecurityKey: "Usar a chave de segurança",
  securityKeyNoAnswer: "A chave de segurança não respondeu. Tente de novo.",
  securityKeyUnavailable: "Este navegador não consegue usar chaves de segurança. Entre por outro navegador.",
  signInWithPasskey: "Entrar com uma chave de acesso",
  passkeyNoAnswer: "A chave de acesso não respondeu. Tente de novo, ou digite seu e-mail ou nome de usuário.",
  emailMeACode: "Enviar um código por e-mail",
  emailMeALink: "Enviar um link por e-mail",
  typeAddressFirst: "Digite seu e-mail primeiro.",
  emailCodeSent: (email: string) => `Se ${email} tiver uma conta aqui, enviamos um código para ele.`,
  emailCodeLabel: "Código da mensagem",
  emailCodeHint: "Seis dígitos. O código funciona uma única vez, por dez minutos.",
  emailLinkSent: (email: string) =>
    `Se ${email} tiver uma conta aqui, enviamos um link para ele. Abra-o neste navegador em até dez minutos.`,
  sendAnotherCode: "Enviar outro código",
  sendAnotherLink: "Enviar outro link",
  signInLinkTitle: "Entrando",
  signInLinkElsewhere:
    "Este link só funciona no navegador em que foi pedido, por dez minutos. Abra-o lá, ou entre por aqui.",
  signInLinkRefused: "Esse link não funcionou. Ele pode já ter sido usado, ou ter expirado.",
  methodNotOffered: "Esta forma de entrar não é oferecida aqui.",
  enrollLead:
    "Sua organização exige um segundo fator, e você ainda não tem nenhum. Configure um para terminar de entrar. Ele será pedido em todas as próximas entradas.",
  enrollKeysLead: "Ou use uma chave de segurança, ou uma chave de acesso guardada neste dispositivo ou no seu celular.",
  confirmAndSignIn: "Confirmar e entrar",
  chooseAnotherWay: "Escolher outra forma",
  nothingToSetUp: "Este navegador não consegue configurar um segundo fator aqui. Entre por outro navegador.",
  enrollmentNotNeeded: "Agora você tem um segundo fator. Entre de novo para usá-lo.",

  registerTitle: "Criar uma conta",
  registerLead: "Informe seu endereço de email. Uma mensagem vai levar um link para você terminar.",
  emailLabel: "Endereço de email",
  sendLink: "Enviar o link",
  alreadyRegistered: "Já tem uma conta?",
  registerForApplication:
    "Um aplicativo trouxe você aqui. Depois de escolher sua senha e entrar, você volta para ele.",
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
  acceptInvitationTitle: (organization: string) => `Entrar em ${organization}`,
  invitationFor: (email: string) => `Este convite foi enviado para ${email}.`,
  invitationNewAccount: "Escolha uma senha para criar sua conta e entrar.",
  createAccountAndJoin: "Criar a conta e entrar",
  join: "Entrar",
  invitationSignIn: (email: string) => `Entre como ${email} e depois abra de novo o link da mensagem.`,
  invitationOtherAccount: (email: string) =>
    `Você entrou com outra conta. Saia, entre como ${email} e depois abra de novo o link da mensagem.`,
  invitationHasAccount: "Entre para aceitar: este endereço já tem uma conta.",
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
  givenConsentsTitle: "Aplicativos que você deixou entrar",
  givenConsentsNone: "Você não deixou nenhum aplicativo entrar na sua conta.",
  givenConsent: (application: string, until: string) => `${application}, até ${until}`,
  withdrawConsent: (application: string) => `Retirar ${application}`,
  signInAt: (application: string) => `Entrar em ${application}`,
  consentWithdrawn: (application: string) =>
    `${application} não tem mais acesso. Ele vai pedir de novo se precisar.`,

  consentTitle: (application: string) => `${application} quer acessar a sua conta`,
  consentLead: "Se você permitir, ele vai poder:",
  consentOffline: "Manter este acesso quando você não estiver usando",
  consentScopeOpenid: "Saber quem você é",
  consentScopeProfile: "Ver o seu nome, o seu nome de usuário e os outros dados do seu perfil",
  consentScopeEmail: "Ver o seu endereço de email",
  consentScopeAddress: "Ver o seu endereço postal",
  consentScopePhone: "Ver o seu número de telefone",
  consentScopeGroups: "Ver os grupos de que você faz parte",
  consentScopeOfResource: (description: string, resourceServer: string) =>
    resourceServer === "" ? description : `${description} (${resourceServer})`,
  consentAllow: "Permitir",
  consentDeny: "Negar",
  consentSelfNamed:
    "Este aplicativo escolheu sozinho este nome e esta imagem. Ninguém aqui verificou quem o mantém.",
  consentHomePage: "A página do aplicativo",
  consentPrivacyPolicy: "A política de privacidade do aplicativo",
  consentTerms: "Os termos de uso do aplicativo",
  opensInNewTab: "(abre em uma nova aba)",
  consentNothingTitle: "Nada para responder",
  consentNothing: "Nenhum aplicativo está esperando a sua resposta neste navegador.",
  goToAccount: "Ir para a sua conta",

  signOutTitle: "Sair?",
  signOutQuestion: (tenant) => `Uma aplicação pediu para você sair de ${tenant}. Sair aqui também?`,
  staySignedIn: "Continuar conectado",
  securityLink: "Segundos fatores e códigos de recuperação",
  profileLink: "Seu nome, endereços e telefone",
  profileTitle: "Seus dados",
  profileLead:
    "Os aplicativos que você deixou entrar podem ler estes dados quando você permitir. Nada aqui é obrigatório; deixe de fora o que preferir não informar.",
  profileNamesHeading: "Nomes",
  profileAboutHeading: "Sobre você",
  profilePagesHeading: "Páginas e foto",
  profilePhoneHeading: "Telefone",
  profileAddressHeading: "Endereço postal",
  claimLabel: (field: string): string => {
    switch (field) {
      case "given_name":
        return "Nome";
      case "middle_name":
        return "Nome do meio";
      case "family_name":
        return "Sobrenome";
      case "nickname":
        return "Apelido";
      case "gender":
        return "Gênero";
      case "birthdate":
        return "Data de nascimento";
      case "zoneinfo":
        return "Fuso horário";
      case "profile":
        return "Sua página em outro lugar";
      case "picture":
        return "Endereço da sua foto";
      case "website":
        return "Site";
      case "phone_number":
        return "Número de telefone";
      case "address.formatted":
        return "O endereço inteiro, como numa carta";
      case "address.street_address":
        return "Rua e número";
      case "address.locality":
        return "Cidade";
      case "address.region":
        return "Estado";
      case "address.postal_code":
        return "CEP";
      case "address.country":
        return "País";
      default:
        return field;
    }
  },
  claimHint: (field: string): string | null => {
    switch (field) {
      case "birthdate":
        return "Escrita AAAA-MM-DD, como 1990-04-12, ou só o ano.";
      case "zoneinfo":
        return "Como o banco de dados de fusos horários o nomeia, como America/Sao_Paulo.";
      case "profile":
      case "picture":
      case "website":
        return "Um endereço inteiro, começando com https://.";
      case "phone_number":
        return "Com + e o código do país, como +55 11 91234 5678.";
      default:
        return null;
    }
  },
  claimInvalid: (label: string) => `${label}: não está escrito de um jeito que possa ser guardado.`,
  phoneVerified: "Sua organização confirmou este número.",
  phoneNotVerified: "Ninguém confirmou este número ainda.",
  profileSave: "Salvar",
  profileSaved: "Seus dados foram salvos.",
  securityTitle: "Segundos fatores",
  backToAccount: "Voltar para a sua conta",
  signInAgainLead: "Para mudar isto, entre de novo antes. As mudanças ficam liberadas por cinco minutos depois que você entra.",
  signInAgain: "Entrar de novo",
  applicationHeading: "Aplicativo autenticador",
  applicationInUse: "Um aplicativo autenticador está configurado.",
  applicationNotInUse: "Nenhum aplicativo autenticador está configurado.",
  setUpApplication: "Configurar um aplicativo autenticador",
  replaceApplication: "Configurar um novo no lugar dele",
  removeApplication: "Remover o aplicativo autenticador",
  setUpLead: "Leia este código com o seu aplicativo autenticador, ou digite nele a chave abaixo. Depois digite o código que ele mostra.",
  qrLabel: "Código QR para ler com o seu aplicativo autenticador",
  secretLabel: "Chave para digitar à mão",
  confirmApplication: "Confirmar",
  cancel: "Cancelar",
  keysHeading: "Chaves de segurança e chaves de acesso",
  noKeys: "Nenhuma chave de segurança ou chave de acesso foi adicionada.",
  keyKindPasskey: "Chave de acesso",
  keyKindSecurityKey: "Chave de segurança",
  keyAdded: (moment) => `Adicionada em ${moment}.`,
  keyLastUsed: (moment) => `Usada pela última vez em ${moment}.`,
  keyNeverUsed: "Ainda não usada.",
  keyNameLabel: "Nome da chave",
  keyNameHint: "Para você distinguir as suas chaves.",
  defaultKeyName: "Chave de segurança",
  defaultPasskeyName: "Chave de acesso",
  addSecurityKey: "Adicionar uma chave de segurança",
  addPasskey: "Adicionar uma chave de acesso",
  keyNoAnswer: "A chave não respondeu, ou já foi adicionada. Tente de novo.",
  renameKey: (name) => `Renomear ${name}`,
  removeKey: (name) => `Remover ${name}`,
  save: "Salvar",
  recoveryHeading: "Códigos de recuperação",
  recoveryRemaining: (count) =>
    count === 1 ? "Resta um código não usado." : `Restam ${count} códigos não usados.`,
  recoveryNone: "Você não tem códigos de recuperação. Eles vêm com o seu primeiro segundo fator.",
  generateCodes: "Gerar novos códigos",
  generateCodesLead: "Os códigos que você tem agora deixam de funcionar.",
  codesTitle: "Seus códigos de recuperação",
  codesLead:
    "Anote ou imprima, e guarde em um lugar seguro. Cada um funciona uma vez, no lugar do seu segundo fator. Eles não são mostrados de novo.",
  codesKept: "Já guardei",
  removeTitle: (what) => `Remover ${what}?`,
  removeLead: "Você não vai mais poder usar para entrar.",
  removeLastLead: "É o seu último segundo fator: os seus códigos de recuperação vão junto.",
  keepIt: "Manter",
  theApplication: "o aplicativo autenticador",
  changed: "Feito.",
  recentSignInRequired: "Entre de novo para fazer esta mudança.",
  lastSecondFactor: "Este é o seu último segundo fator e a sua organização exige um. Adicione outro antes.",
  totpCodeWrong: "Esse não é o código que o aplicativo mostra.",
  enrollmentExpired: "A configuração demorou demais. Comece de novo.",
  keyNameInvalid: "Este nome não pode ser usado.",

  noticeRegistered: "Sua conta está pronta. Entre para continuar.",
  noticePasswordChanged: "Sua senha foi trocada. Entre com a nova.",
  noticeSignedOut: "Você saiu.",
  noticeProviderRefused: "Não deu certo. Tente de novo ou entre de outra forma.",
  noticeProviderCancelled: "A entrada não foi concluída no provedor.",

  or: "ou",
  continueWith: (provider) => `Continuar com ${provider}`,
  comingBackTitle: "Entrando",
  directoryIdentifierLabel: (directory) => `Usuário em ${directory}`,
  otherWays: "Outras formas de entrar",

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
