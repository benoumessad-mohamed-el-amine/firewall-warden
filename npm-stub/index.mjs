// This package is a pointer, not warden. Importing it should fail loudly
// with directions rather than with a cryptic module-resolution error.
throw new Error(
  [
    '@askalf/warden is not distributed on npm — this package is a pointer.',
    '',
    'Install the Sigstore-signed release instead:',
    "  gh release download --repo askalf/warden --pattern 'warden.tgz*'",
    '  gh attestation verify warden.tgz --owner askalf',
    '  npm i -g ./warden.tgz',
    '',
    'Why: https://github.com/askalf/warden#readme',
  ].join('\n')
);
