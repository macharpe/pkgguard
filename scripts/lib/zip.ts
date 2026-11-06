import { createWriteStream } from "node:fs";
import { once } from "node:events";
import yauzl from "yauzl";

/** Streams every `.json` entry of a zip to `onRecord` without loading the archive into memory. */
export async function forEachJsonEntry(
  zipPath: string,
  onRecord: (name: string, json: string) => void | Promise<void>,
): Promise<number> {
  const zip = await new Promise<yauzl.ZipFile>((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true, autoClose: true }, (err, z) => (err || !z ? reject(err) : resolve(z)));
  });

  let count = 0;
  const next = (): void => zip.readEntry();

  return new Promise<number>((resolve, reject) => {
    const fail = (err: unknown): void => {
      zip.close();
      reject(err);
    };
    zip.on("error", fail);
    zip.on("end", () => resolve(count));
    zip.on("entry", (entry: yauzl.Entry) => {
      if (!entry.fileName.endsWith(".json")) return next();
      zip.openReadStream(entry, (err, stream) => {
        if (err || !stream) return reject(err);
        const chunks: Buffer[] = [];
        stream.on("data", (c: Buffer) => chunks.push(c));
        stream.on("error", reject);
        stream.on("end", () => {
          new Promise<void>((done) => done(onRecord(entry.fileName, Buffer.concat(chunks).toString("utf8"))))
            .then(() => {
              count++;
              next();
            })
            .catch(fail);
        });
      });
    });
    next();
  });
}

export async function writeLines(path: string, lines: Iterable<string>): Promise<void> {
  const out = createWriteStream(path);
  for (const line of lines) {
    if (!out.write(line + "\n")) await once(out, "drain");
  }
  out.end();
  await once(out, "finish");
}
