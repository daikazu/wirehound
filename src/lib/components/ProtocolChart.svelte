<script>
  import { Chart, registerables } from 'chart.js';
  import { stats } from '$lib/stores/stats.js';

  Chart.register(...registerables);

  const PROTOCOL_COLORS = {
    TCP: '#4fc3f7',
    UDP: '#81c784',
    DNS: '#ffb74d',
    HTTP: '#e57373',
    HTTPS: '#ba68c8',
    ICMP: '#fff176',
    ARP: '#90a4ae',
  };

  const DEFAULT_COLOR = '#666';

  let canvasEl = $state(null);
  let chart = $state(null);

  $effect(() => {
    if (!canvasEl) return;

    chart = new Chart(canvasEl, {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: [],
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 0 },
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#aaa',
              font: { size: 11 },
              padding: 8,
              boxWidth: 12,
            },
          },
        },
        cutout: '60%',
      },
    });

    return () => {
      chart?.destroy();
    };
  });

  $effect(() => {
    const breakdown = $stats.protocol_breakdown;
    if (!chart || !breakdown) return;

    const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);
    const labels = entries.map(e => e[0]);
    const data = entries.map(e => e[1]);
    const colors = labels.map(l => PROTOCOL_COLORS[l] || DEFAULT_COLOR);

    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.data.datasets[0].backgroundColor = colors;
    chart.update('none');
  });
</script>

<div class="protocol-chart">
  <div class="chart-title">Protocols</div>
  <div class="chart-container">
    <canvas bind:this={canvasEl}></canvas>
  </div>
</div>

<style>
  .protocol-chart {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .chart-title {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 8px 10px 4px;
  }

  .chart-container {
    flex: 1;
    padding: 0 10px 10px;
    min-height: 0;
    position: relative;
  }
</style>
