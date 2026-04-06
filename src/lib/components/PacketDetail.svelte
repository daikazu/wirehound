<script>
  import { selectedPacket } from '$lib/stores/packets.js';

  let expandedLayers = $state(/** @type {Set<number>} */ (new Set()));

  // Expand all layers when a new packet is selected
  $effect(() => {
    const pkt = $selectedPacket;
    if (pkt && pkt.parsed_layers) {
      expandedLayers = new Set(pkt.parsed_layers.map((_, i) => i));
    } else {
      expandedLayers = new Set();
    }
  });

  function toggleLayer(index) {
    const next = new Set(expandedLayers);
    if (next.has(index)) {
      next.delete(index);
    } else {
      next.add(index);
    }
    expandedLayers = next;
  }

  function formatHex(bytes) {
    if (!bytes || bytes.length === 0) return '';
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const chunk = bytes.slice(offset, offset + 16);
      const hex = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
      const offsetStr = offset.toString(16).padStart(8, '0');
      lines.push(`${offsetStr}  ${hex.padEnd(48)}  ${ascii}`);
    }
    return lines.join('\n');
  }
</script>

<div class="packet-detail">
  {#if $selectedPacket}
    <div class="detail-content">
      <div class="layers-panel">
        <div class="panel-header">Packet Layers</div>
        {#each $selectedPacket.parsed_layers as layer, i}
          <div class="layer">
            <button class="layer-header" onclick={() => toggleLayer(i)}>
              <span class="toggle">{expandedLayers.has(i) ? '▾' : '▸'}</span>
              {layer.name}
            </button>
            {#if expandedLayers.has(i)}
              <div class="layer-fields">
                {#each layer.fields as [key, value]}
                  <div class="field-row">
                    <span class="field-key">{key}:</span>
                    <span class="field-value">{value}</span>
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      </div>

      <div class="hex-panel">
        <div class="panel-header">Hex Dump ({$selectedPacket.raw_bytes.length} bytes)</div>
        <pre class="hex-dump">{formatHex($selectedPacket.raw_bytes)}</pre>
      </div>
    </div>
  {:else}
    <div class="empty-state">
      Select a packet to view details
    </div>
  {/if}
</div>

<style>
  .packet-detail {
    height: 100%;
    overflow: hidden;
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 12px;
    color: #e0e0e0;
    background: #0d0d18;
  }

  .detail-content {
    display: flex;
    height: 100%;
    gap: 1px;
    background: #2a2a4a;
  }

  .layers-panel {
    flex: 1;
    overflow-y: auto;
    background: #0d0d18;
  }

  .hex-panel {
    flex: 1;
    overflow-y: auto;
    background: #0d0d18;
  }

  .panel-header {
    padding: 6px 10px;
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid #2a2a4a;
    background: #1a1a2e;
    position: sticky;
    top: 0;
  }

  .layer {
    border-bottom: 1px solid #1a1a2e;
  }

  .layer-header {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 5px 10px;
    background: none;
    border: none;
    color: #00d4ff;
    font-size: 12px;
    font-family: inherit;
    cursor: pointer;
    text-align: left;
  }

  .layer-header:hover {
    background: #1a1a2e;
  }

  .toggle {
    font-size: 10px;
    width: 12px;
  }

  .layer-fields {
    padding: 2px 10px 6px 28px;
  }

  .field-row {
    padding: 1px 0;
    display: flex;
    gap: 8px;
  }

  .field-key {
    color: #888;
    flex-shrink: 0;
  }

  .field-value {
    color: #e0e0e0;
    word-break: break-all;
  }

  .hex-dump {
    padding: 8px 10px;
    margin: 0;
    white-space: pre;
    color: #aaa;
    line-height: 1.6;
  }

  .empty-state {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: #555;
    font-size: 14px;
  }
</style>
