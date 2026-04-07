<script>
  import { packets, selectedPacket } from '$lib/stores/packets.js';
  import { displayFilter } from '$lib/stores/capture.js';

  const ROW_HEIGHT = 28;

  let containerEl = $state(null);
  let containerHeight = $state(400);
  let scrollTop = $state(0);

  const PROTOCOL_COLORS = {
    TCP: '#4fc3f7',
    UDP: '#81c784',
    DNS: '#ffb74d',
    HTTP: '#e57373',
    HTTPS: '#ba68c8',
    ICMP: '#fff176',
    ARP: '#90a4ae',
  };

  let filteredPackets = $derived.by(() => {
    const filter = $displayFilter.trim().toLowerCase();
    if (!filter) return $packets;
    return $packets.filter(p => {
      const proto = typeof p.protocol === 'string' ? p.protocol : (p.protocol.Other || '');
      return (
        proto.toLowerCase().includes(filter) ||
        p.src_ip.toLowerCase().includes(filter) ||
        p.dst_ip.toLowerCase().includes(filter) ||
        p.summary.toLowerCase().includes(filter) ||
        String(p.src_port).includes(filter) ||
        String(p.dst_port).includes(filter)
      );
    });
  });

  let totalHeight = $derived(filteredPackets.length * ROW_HEIGHT);
  let visibleCount = $derived(Math.ceil(containerHeight / ROW_HEIGHT) + 2);
  let startIndex = $derived(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 1));
  let visiblePackets = $derived(filteredPackets.slice(startIndex, startIndex + visibleCount));

  $effect(() => {
    if (!containerEl) return;
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        containerHeight = entry.contentRect.height;
      }
    });
    observer.observe(containerEl);
    return () => observer.disconnect();
  });

  function onScroll(e) {
    scrollTop = e.target.scrollTop;
  }

  function getProtocolName(proto) {
    return typeof proto === 'string' ? proto : (proto.Other || 'Unknown');
  }

  function getProtocolColor(proto) {
    const name = getProtocolName(proto);
    return PROTOCOL_COLORS[name] || '#aaa';
  }

  function formatTime(timestamp) {
    try {
      const d = new Date(timestamp);
      return d.toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 });
    } catch {
      return timestamp;
    }
  }

  function selectPacket(packet) {
    selectedPacket.set(packet);
  }
</script>

<div class="packet-list-wrapper">
  <div class="header-row">
    <span class="col-id">#</span>
    <span class="col-time">Time</span>
    <span class="col-src">Source</span>
    <span class="col-dst">Destination</span>
    <span class="col-proto">Protocol</span>
    <span class="col-len">Length</span>
    <span class="col-info">Info</span>
  </div>
  <div class="scroll-container" bind:this={containerEl} onscroll={onScroll}>
    <div class="virtual-spacer" style="height: {totalHeight}px">
      <div class="visible-rows" style="transform: translateY({startIndex * ROW_HEIGHT}px)">
        {#each visiblePackets as pkt (pkt.id)}
          <div
            class="packet-row"
            class:selected={$selectedPacket?.id === pkt.id}
            onclick={() => selectPacket(pkt)}
            style="height: {ROW_HEIGHT}px"
          >
            <span class="col-id">{pkt.id}</span>
            <span class="col-time">{formatTime(pkt.timestamp)}</span>
            <span class="col-src">{pkt.src_ip}{pkt.src_port != null ? ':' + pkt.src_port : ''}</span>
            <span class="col-dst">{pkt.dst_ip}{pkt.dst_port != null ? ':' + pkt.dst_port : ''}</span>
            <span class="col-proto" style="color: {getProtocolColor(pkt.protocol)}">
              {getProtocolName(pkt.protocol)}
            </span>
            <span class="col-len">{pkt.length}</span>
            <span class="col-info">{pkt.summary}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>

<style>
  .packet-list-wrapper {
    display: flex;
    flex-direction: column;
    height: 100%;
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 12px;
    color: #e0e0e0;
  }

  .header-row {
    display: flex;
    align-items: center;
    height: 28px;
    padding: 0 8px;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
    font-weight: 600;
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }

  .scroll-container {
    flex: 1;
    overflow-y: auto;
  }

  .virtual-spacer {
    position: relative;
  }

  .visible-rows {
    position: absolute;
    width: 100%;
  }

  .packet-row {
    display: flex;
    align-items: center;
    padding: 0 8px;
    cursor: pointer;
    border-bottom: 1px solid #1a1a2e;
  }

  .packet-row:hover {
    background: #1a1a2e;
  }

  .packet-row.selected {
    background: #00d4ff15;
    outline: 1px solid #00d4ff40;
  }

  .col-id { width: 60px; flex-shrink: 0; }
  .col-time { width: 110px; flex-shrink: 0; }
  .col-src { width: 160px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-dst { width: 160px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-proto { width: 80px; flex-shrink: 0; font-weight: 600; }
  .col-len { width: 70px; flex-shrink: 0; text-align: right; }
  .col-info { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #aaa; }
</style>
