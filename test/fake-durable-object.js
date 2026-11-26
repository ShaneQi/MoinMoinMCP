// A Durable Object namespace for tests: one UploadStore per name, each with an
// in-memory storage that has the key-value API and an alarm, like the real one.
import { UploadStore } from "../src/uploads.js";

function memoryStorage() {
  const data = new Map();
  const s = {
    data,
    alarm: null,
    async get(key) { return data.has(key) ? structuredClone(data.get(key)) : undefined; },
    async put(entries) { for (const [k, v] of Object.entries(entries)) data.set(k, structuredClone(v)); },
    async deleteAll() { data.clear(); },
    async setAlarm(t) { s.alarm = t; },
    async deleteAlarm() { s.alarm = null; },
  };
  return s;
}

export function fakeNamespace() {
  const objects = new Map();
  return {
    objects,
    idFromName: (name) => name,
    get(id) {
      if (!objects.has(id)) {
        const storage = memoryStorage();
        const store = new UploadStore({ storage });
        storage.fireAlarm = () => store.alarm();
        objects.set(id, storage);
        storage.store = store;
      }
      const store = objects.get(id).store;
      return { fetch: (url, init) => store.fetch(new Request(url, init)) };
    },
  };
}
