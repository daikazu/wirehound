import { writable } from 'svelte/store';

const MAX_PACKETS = 10_000;

function createPacketStore() {
  const { subscribe, update, set } = writable(/** @type {any[]} */ ([]));

  return {
    subscribe,
    add(packet) {
      update(packets => {
        const next = [...packets, packet];
        if (next.length > MAX_PACKETS) {
          return next.slice(next.length - MAX_PACKETS);
        }
        return next;
      });
    },
    clear() {
      set([]);
    },
  };
}

export const packets = createPacketStore();
export const selectedPacket = writable(/** @type {any} */ (null));
