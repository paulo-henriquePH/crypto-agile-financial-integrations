// Independent library comparison, never imports the Python implementation.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const base = path.dirname(here);
const modulePath = process.argv[2];
if (!modulePath) throw new Error('Pass path to canonicalize/lib/canonicalize.js');
const canonicalize = (await import(pathToFileURL(path.resolve(modulePath)).href)).default;
const packageInfo = JSON.parse(fs.readFileSync(path.resolve(modulePath, '../../package.json'), 'utf8'));
if (packageInfo.version !== '5.1.0') throw new Error('Expected canonicalize 5.1.0');
const manifestPath = path.join(base, 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const write = process.argv.includes('--write-expectations');
for (const item of manifest.cases.filter(x => x.valid)) {
  const input = JSON.parse(fs.readFileSync(path.join(base, item.input), 'utf8'));
  const value = item.mode === 'envelope' ? {protected: input.protected, payload: input.payload} : input;
  const actual = Buffer.from(canonicalize(value), 'utf8');
  const hash = createHash('sha256').update(actual).digest('hex');
  const expectedPath = path.join(base, item.expected);
  if (write) {
    fs.writeFileSync(expectedPath, actual);
    item.sha256 = hash;
  } else if (!actual.equals(fs.readFileSync(expectedPath)) || hash !== item.sha256) {
    throw new Error('Independent comparison failed: ' + item.name);
  }
  console.log(JSON.stringify({case: item.name, bytes: actual.length, sha256: hash, result: 'PASS'}));
}
if (write) fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
