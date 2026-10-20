import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

// Shell-string process APIs are banned project-wide: scanned repos are untrusted input, so `git`
// must always be spawned with execFile/spawn and an argv array.
const bannedChildProcess = {
  importNames: ['exec', 'execSync'],
  message: 'Use execFile/spawn with an argv array; never a shell string.',
};

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/', '.fixtures/', 'leak-report/', 'examples/'] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  prettier,
  {
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'node:child_process', ...bannedChildProcess },
            { name: 'child_process', ...bannedChildProcess },
          ],
        },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', destructuredArrayIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['test/**/*.ts', 'bench/**/*.ts'],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },
);
