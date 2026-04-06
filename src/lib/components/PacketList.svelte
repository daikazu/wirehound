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

<div class="packet-list" bind:this={containerEl} onscroll={onScroll}>
  <div class="virtual-spacer" style="height: {totalHeight}px">
    <table>
      <thead>
        <tr>
          <th class="col-id">#</th>
          <th class="col-time">Time</th>
          <th class="col-src">Source</th>
          <th class="col-dst">Destination</th>
          <th class="col-proto">Protocol</th>
          <th class="col-len">Length</th>
          <th class="col-info">Info</th>
        </tr>
      </thead>
      <tbody style="transform: translateY({startIndex * ROW_HEIGHT}px)">
        {#each visiblePackets as pkt (pkt.id)}
          <tr
            class="packet-row"
            class:selected={$selectedPacket?.id === pkt.id}
            onclick={() => selectPacket(pkt)}
            style="height: {ROW_HEIGHT}px"
          >
            <td class="col-id">{pkt.id}</td>
            <td class="col-time">{formatTime(pkt.timestamp)}</td>
            <td class="col-src">{pkt.src_ip}{pkt.src_port != null ? ':' + pkt.src_port : ''}</td>
            <td class="col-dst">{pkt.dst_ip}{pkt.dst_port != null ? ':' + pkt.dst_port : ''}</td>
            <td class="col-proto">
              <span class="proto-badge" style="color: {getProtocolColor(pkt.protocol)}">
                {getProtocolName(pkt.protocol)}
              </span>
            </td>
            <td class="col-len">{pkt.length}</td>
            <td class="col-info">{pkt.summary}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<style>
  .packet-list {
    overflow-y: auto;
    height: 100%;
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 12px;
    color: #e0e0e0;
  }

  .virtual-spacer {
    position: relative;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }

  thead {
    position: sticky;
    top: 0;
    z-index: 1;
  }

  th {
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
    padding: 4px 8px;
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
    height: 28px;
  }

  td {
    padding: 0 8px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-id { width: 60px; }
  .col-time { width: 110px; }
  .col-src { width: 160px; }
  .col-dst { width: 160px; }
  .col-proto { width: 80px; }
  .col-len { width: 70px; text-align: right; }
  .col-info { width: auto; }

  .packet-row {
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

  .proto-badge {
    font-weight: 600;
  }
</style>
