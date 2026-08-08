import { open } from 'node:fs/promises';

const handle = await open('../internal/frontend/dist/.placeholder', 'a');
await handle.close();
