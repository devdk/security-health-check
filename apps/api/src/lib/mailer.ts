import type { FastifyBaseLogger } from 'fastify';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

/** Adapter boundary: swap in an SMTP or API-based sender later without touching callers. */
export interface Mailer {
  send(message: MailMessage): Promise<void>;
}

/** Development transport: writes the email to the log instead of sending it. */
export class ConsoleMailer implements Mailer {
  constructor(private readonly log: Pick<FastifyBaseLogger, 'info'>) {}

  async send(message: MailMessage): Promise<void> {
    this.log.info({ mail: { to: message.to, subject: message.subject } }, `\n----- EMAIL (console transport) -----\n${message.text}\n-------------------------------------`);
  }
}

/** Collects messages in memory. Used by tests. */
export class MemoryMailer implements Mailer {
  readonly sent: MailMessage[] = [];

  async send(message: MailMessage): Promise<void> {
    this.sent.push(message);
  }

  lastTo(email: string): MailMessage | undefined {
    return this.sent.filter((m) => m.to === email).at(-1);
  }
}
