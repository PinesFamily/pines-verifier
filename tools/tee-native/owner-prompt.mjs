// Terminal prompts for the owner-run key tools. Secrets are typed at a TTY with echo off and never come from argv or
// the environment; a test injects its own `prompts` object instead (there is deliberately no non-interactive switch).
import {stdin, stdout} from 'node:process';
import {createInterface} from 'node:readline/promises';

export class PromptError extends Error {constructor(code) {super(code); this.code = code;}}
/** `{ask, askHidden}` bound to the controlling terminal; refuses to run without one. */
export function terminalPrompts({input = stdin, output = stdout} = {}) {
  if (!input.isTTY || !output.isTTY) throw new PromptError('TERMINAL_REQUIRED');
  return {
    async ask(question) {
      const rl = createInterface({input, output});
      try {return (await rl.question(question)).trim();} finally {rl.close();}
    },
    /** Raw mode, no echo: characters are collected until Enter; Ctrl-C and Ctrl-D abort. */
    askHidden(question) {
      return new Promise((resolve, reject) => {
        output.write(question);
        const chars = [];
        const wasRaw = input.isRaw;
        input.setRawMode(true); input.resume(); input.setEncoding('utf8');
        const finish = (error) => {
          input.removeListener('data', onData); input.setRawMode(wasRaw === true); input.pause(); output.write('\n');
          if (error) reject(error); else resolve(chars.join(''));
          chars.fill('\0'); chars.length = 0;
        };
        const onData = chunk => {
          for (const char of chunk) {
            if (char === '\u0003' || char === '\u0004') return finish(new PromptError('PROMPT_ABORTED'));
            if (char === '\r' || char === '\n') return finish();
            if (char === '\u007f' || char === '\b') {chars.pop(); continue;}
            chars.push(char);
          }
        };
        input.on('data', onData);
      });
    },
  };
}
