/* ==========================================================================
   Charts - hand-drawn inline SVG.
   No charting library: the platform runs offline, so every pixel is generated
   here. Each function returns an SVG string ready to drop into innerHTML.
   ========================================================================== */
(function (DXB) {
    'use strict';

    var esc = DXB.esc;
    var attr = DXB.attr;

    var PALETTE = {
        critical: '#f43f5e', high: '#fb923c', medium: '#facc15', low: '#60a5fa', info: '#94a3b8',
        accent: '#2dd4bf', accent2: '#14b8a6', ok: '#34d399', warn: '#fbbf24', bad: '#f87171',
        grid: '#233043', text: '#8494a7', ink: '#e8eef5'
    };

    var SERIES = ['#2dd4bf', '#60a5fa', '#a78bfa', '#fb923c', '#f472b6', '#facc15', '#34d399', '#f87171', '#94a3b8', '#22d3ee'];

    function polar(cx, cy, r, angleDeg) {
        var rad = (angleDeg - 90) * Math.PI / 180;
        return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
    }

    function arcPath(cx, cy, rOuter, rInner, startAngle, endAngle) {
        // Full circle needs two arcs; SVG cannot draw 360 degrees in one.
        if (endAngle - startAngle >= 359.999) { endAngle = startAngle + 359.999; }
        var so = polar(cx, cy, rOuter, endAngle);
        var eo = polar(cx, cy, rOuter, startAngle);
        var si = polar(cx, cy, rInner, startAngle);
        var ei = polar(cx, cy, rInner, endAngle);
        var large = endAngle - startAngle > 180 ? 1 : 0;
        return [
            'M', so.x.toFixed(2), so.y.toFixed(2),
            'A', rOuter, rOuter, 0, large, 0, eo.x.toFixed(2), eo.y.toFixed(2),
            'L', si.x.toFixed(2), si.y.toFixed(2),
            'A', rInner, rInner, 0, large, 1, ei.x.toFixed(2), ei.y.toFixed(2),
            'Z'
        ].join(' ');
    }

    /**
     * Donut chart.
     * data: [{label, value, colour?}]
     */
    function donut(data, options) {
        options = options || {};
        var size = options.size || 190;
        var cx = size / 2, cy = size / 2;
        var rOuter = size / 2 - 4;
        var rInner = rOuter * (options.thickness || 0.62);
        var total = data.reduce(function (sum, d) { return sum + (Number(d.value) || 0); }, 0);

        if (total <= 0) {
            return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '" role="img" aria-label="No data">' +
                '<circle cx="' + cx + '" cy="' + cy + '" r="' + ((rOuter + rInner) / 2) + '" fill="none" stroke="' + PALETTE.grid + '" stroke-width="' + (rOuter - rInner) + '"/>' +
                '<text x="' + cx + '" y="' + (cy + 5) + '" text-anchor="middle" fill="' + PALETTE.text + '" font-size="12">No data</text></svg>';
        }

        var angle = 0;
        var slices = data.filter(function (d) { return Number(d.value) > 0; }).map(function (d, i) {
            var sweep = (Number(d.value) / total) * 360;
            var colour = d.colour || PALETTE[d.label] || SERIES[i % SERIES.length];
            var path = arcPath(cx, cy, rOuter, rInner, angle, angle + sweep);
            angle += sweep;
            return '<path d="' + path + '" fill="' + attr(colour) + '" stroke="#0b0f14" stroke-width="1.5">' +
                   '<title>' + esc(DXB.fmt.label(d.label)) + ': ' + esc(d.value) + '</title></path>';
        }).join('');

        var centreValue = options.centreValue !== undefined ? options.centreValue : total;
        var centreLabel = options.centreLabel || 'total';

        return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '" role="img">' +
            slices +
            '<text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" fill="' + PALETTE.ink + '" font-size="' + (size / 6) + '" font-weight="700">' + esc(centreValue) + '</text>' +
            '<text x="' + cx + '" y="' + (cy + 15) + '" text-anchor="middle" fill="' + PALETTE.text + '" font-size="10" letter-spacing="1">' + esc(String(centreLabel).toUpperCase()) + '</text>' +
        '</svg>';
    }

    /** Legend to accompany a donut. */
    function legend(data, options) {
        options = options || {};
        var total = data.reduce(function (s, d) { return s + (Number(d.value) || 0); }, 0);
        return '<div style="display:flex;flex-direction:column;gap:6px">' + data.map(function (d, i) {
            var colour = d.colour || PALETTE[d.label] || SERIES[i % SERIES.length];
            var percent = total > 0 ? Math.round(d.value / total * 100) : 0;
            return '<div style="display:flex;align-items:center;gap:8px;font-size:12px">' +
                '<span style="width:10px;height:10px;border-radius:2px;background:' + attr(colour) + ';flex:none"></span>' +
                '<span style="flex:1;color:var(--fg-1)" class="truncate">' + esc(DXB.fmt.label(d.label)) + '</span>' +
                '<b class="tabular">' + esc(d.value) + '</b>' +
                (options.percent === false ? '' : '<span class="dim tabular" style="width:36px;text-align:right">' + percent + '%</span>') +
            '</div>';
        }).join('') + '</div>';
    }

    /**
     * Horizontal bar list.
     * data: [{label, value, colour?}]
     */
    function bars(data, options) {
        options = options || {};
        var max = Math.max.apply(null, data.map(function (d) { return Number(d.value) || 0; }).concat([1]));
        return '<div style="display:flex;flex-direction:column;gap:7px">' + data.map(function (d, i) {
            var colour = d.colour || PALETTE[d.label] || SERIES[i % SERIES.length];
            var width = Math.max(Number(d.value) > 0 ? 2 : 0, Math.round((Number(d.value) || 0) / max * 100));
            return '<div style="display:flex;align-items:center;gap:9px;font-size:12px">' +
                '<span style="width:' + (options.labelWidth || 150) + 'px;color:var(--fg-1);flex:none" class="truncate" title="' + attr(d.label) + '">' + esc(d.label) + '</span>' +
                '<span style="flex:1;height:14px;background:var(--bg-3);border-radius:3px;overflow:hidden">' +
                    '<span style="display:block;height:100%;width:' + width + '%;background:' + attr(colour) + ';border-radius:3px"></span>' +
                '</span>' +
                '<b class="tabular" style="width:30px;text-align:right">' + esc(d.value) + '</b>' +
            '</div>';
        }).join('') + '</div>';
    }

    /**
     * Sparkline / area trend.
     * series: [{date, count}]
     */
    function sparkline(series, options) {
        options = options || {};
        var width = options.width || 520;
        var height = options.height || 90;
        var padding = 6;
        if (!series || series.length === 0) {
            return '<div class="dim small">No trend data.</div>';
        }
        var values = series.map(function (p) { return Number(p.count) || 0; });
        var max = Math.max.apply(null, values.concat([1]));
        var stepX = (width - padding * 2) / Math.max(1, series.length - 1);

        var points = values.map(function (v, i) {
            var x = padding + i * stepX;
            var y = height - padding - (v / max) * (height - padding * 2);
            return x.toFixed(1) + ',' + y.toFixed(1);
        });

        var area = 'M' + padding + ',' + (height - padding) + ' L' + points.join(' L') +
                   ' L' + (padding + (series.length - 1) * stepX).toFixed(1) + ',' + (height - padding) + ' Z';

        var dots = values.map(function (v, i) {
            if (v === 0) { return ''; }
            var x = padding + i * stepX;
            var y = height - padding - (v / max) * (height - padding * 2);
            return '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="2.5" fill="' + PALETTE.accent + '">' +
                   '<title>' + esc(series[i].date) + ': ' + v + '</title></circle>';
        }).join('');

        return '<svg viewBox="0 0 ' + width + ' ' + height + '" width="100%" height="' + height + '" preserveAspectRatio="none" role="img">' +
            '<defs><linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">' +
                '<stop offset="0%" stop-color="' + PALETTE.accent + '" stop-opacity=".32"/>' +
                '<stop offset="100%" stop-color="' + PALETTE.accent + '" stop-opacity="0"/>' +
            '</linearGradient></defs>' +
            '<path d="' + area + '" fill="url(#sparkFill)"/>' +
            '<polyline points="' + points.join(' ') + '" fill="none" stroke="' + PALETTE.accent + '" stroke-width="1.8" stroke-linejoin="round"/>' +
            dots +
        '</svg>' +
        '<div class="flex small dim" style="justify-content:space-between;margin-top:2px">' +
            '<span>' + esc(series[0].date) + '</span><span>' + esc(series[series.length - 1].date) + '</span>' +
        '</div>';
    }

    /** Semi-circular gauge for the posture score. */
    function gauge(value, options) {
        options = options || {};
        var size = options.size || 170;
        var v = Math.max(0, Math.min(100, Number(value) || 0));
        var cx = size / 2, cy = size / 2;
        var rOuter = size / 2 - 6, rInner = rOuter - 14;

        var colour = v >= 80 ? PALETTE.ok : v >= 60 ? PALETTE.medium : v >= 35 ? PALETTE.high : PALETTE.critical;
        var track = arcPath(cx, cy, rOuter, rInner, 0, 359.99);
        var fill = v > 0 ? arcPath(cx, cy, rOuter, rInner, 0, v * 3.6) : '';

        return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '" role="img" aria-label="Posture score ' + v + ' of 100">' +
            '<path d="' + track + '" fill="' + PALETTE.grid + '"/>' +
            (fill ? '<path d="' + fill + '" fill="' + colour + '"/>' : '') +
            '<text x="' + cx + '" y="' + (cy + 3) + '" text-anchor="middle" fill="' + PALETTE.ink + '" font-size="' + (size / 4.2) + '" font-weight="700">' + v + '</text>' +
            '<text x="' + cx + '" y="' + (cy + 20) + '" text-anchor="middle" fill="' + PALETTE.text + '" font-size="9.5" letter-spacing="1.2">POSTURE /100</text>' +
        '</svg>';
    }

    /**
     * Interactive 5x5 risk matrix.
     * cells: [{likelihood, impact, band, colour}]
     */
    function matrix(cells, options) {
        options = options || {};
        var map = {};
        (cells || []).forEach(function (c) { map[c.likelihood + ':' + c.impact] = c; });

        var likelihoodLabels = { 1: 'Rare', 2: 'Unlikely', 3: 'Possible', 4: 'Likely', 5: 'Almost certain' };
        var impactLabels = { 1: 'Insignificant', 2: 'Minor', 3: 'Moderate', 4: 'Major', 5: 'Severe' };

        var html = '<table class="matrix"><thead><tr><th></th>';
        for (var i = 1; i <= 5; i++) {
            html += '<th>' + i + '<br><span class="dim" style="font-weight:400">' + esc(impactLabels[i]) + '</span></th>';
        }
        html += '</tr></thead><tbody>';

        for (var l = 5; l >= 1; l--) {
            html += '<tr><th style="text-align:right;padding-right:9px">' + l + '<br><span class="dim" style="font-weight:400">' + esc(likelihoodLabels[l]) + '</span></th>';
            for (var im = 1; im <= 5; im++) {
                var cell = map[l + ':' + im] || { band: 'info', colour: '#6b7280', score: l * im };
                var selected = options.selected && options.selected.likelihood === l && options.selected.impact === im;
                html += '<td><div class="cell' + (selected ? ' selected' : '') + '" ' +
                        'style="background:' + attr(cell.colour) + '" ' +
                        'data-l="' + l + '" data-i="' + im + '" ' +
                        'title="Likelihood ' + l + ' x Impact ' + im + ' = ' + (cell.score || l * im) + ' (' + attr(cell.band) + ')">' +
                        esc(String(cell.band).slice(0, 4).toUpperCase()) + '</div></td>';
            }
            html += '</tr>';
        }
        return html + '</tbody></table>';
    }

    /** Stacked coverage bar: pass / fail / manual / n-a / pending. */
    function coverageBar(row) {
        var total = Math.max(1, Number(row.total) || 0);
        var segments = [
            { key: 'pass', colour: PALETTE.ok },
            { key: 'fail', colour: PALETTE.critical },
            { key: 'manual_review', colour: PALETTE.medium },
            { key: 'not_applicable', colour: PALETTE.info },
            { key: 'pending', colour: '#2e3d52' }
        ];
        return '<div style="display:flex;height:14px;border-radius:3px;overflow:hidden;background:var(--bg-3)">' +
            segments.map(function (segment) {
                var value = Number(row[segment.key]) || 0;
                if (value === 0) { return ''; }
                return '<span title="' + attr(DXB.fmt.label(segment.key) + ': ' + value) + '" style="width:' +
                    (value / total * 100).toFixed(2) + '%;background:' + segment.colour + '"></span>';
            }).join('') +
        '</div>';
    }

    DXB.charts = {
        donut: donut,
        legend: legend,
        bars: bars,
        sparkline: sparkline,
        gauge: gauge,
        matrix: matrix,
        coverageBar: coverageBar,
        palette: PALETTE,
        series: SERIES
    };

}(window.DXB));
