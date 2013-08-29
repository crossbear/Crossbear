/*
  First draw malicious traces (without certificate that has been
  confirmed by the server), then draw all non-malicious traces
  intersecting a malicious trace.
*/

function Highlightable(data) {
    for (var prop in data) {
	if (data.hasOwnProperty(prop)) {
	    this[prop] = data[prop];
	}
    }
    this.highlightedBy = [];
}

Highlightable.prototype.isHighlighted = function() {
    return this.highlightedBy.length > 0;
}

Highlightable.prototype.isHighlightedBy = function(source) {
    return this.highlightedBy.indexOf(source) != -1;
}

Highlightable.prototype.highlightBy = function(source) {
    if (! this.isHighlightedBy(source)) {
	this.highlightedBy.push(source);
    }
}

Highlightable.prototype.unhighlightBy = function(source) {
    var index = this.highlightedBy.indexOf(source);
    if (index != -1) {
	this.highlightedBy.splice(index,1);
    }
}

var width = window.innerWidth;
var height = window.innerHeight;
var sampleSVG = d3.select("#viz")
    .append("svg")
    .attr("xmlns", "http://www.w3.org/2000/svg")
    .attr("version", "1.1")
    .attr("width", width)
    .attr("height", height);

var sizescale = d3.scale.linear().domain([0,1,10]).range([5, 7, 30]).clamp(true);


// Add arrow markers to the svg defs
sampleSVG.append("defs").append("marker")
    .attr("id", "endArrow")
    .attr("viewBox", "0 0 10 10")
    .attr("refX", 10)
    .attr("refY", 5)
    .attr('markerWidth', 4)
    .attr('markerHeight', 4)
    .attr('orient', 'auto')
    .append("polyline")
    .attr('points', '0,0 10,5 0,10 1,5')
    .attr('stroke', 'black')
    .attr("fill" ,"black");

var force, nodes = [] , links = [], graphnodes = [], graphlinks = []

function tick(e) {
    graphnodes.attr("cx", function(d) { return d.x; })
	.attr("cy", function(d) { return d.y; })
    
    graphlinks
	.attr("x1", function(d) { return d.source.x; })
	.attr("x2", function(d) { return d.target.x; })
	.attr("y1", function(d) { return d.source.y; })
	.attr("y2", function(d) { return d.target.y; });
};

// Still a bug where highlighted isn't set to false correctly.
// Color trace when selected
function select(d) {
    if (d.start) {
	var source = d.id;
	if (d.isHighlighted()) {
	    // deselect trace
	    links.forEach(function (l) {
		l.unhighlightBy(source);
	    });
	    nodes.forEach(function (n) {
		n.unhighlightBy(source);
	    });
	} else {
	    // select trace
	    links.forEach(function (l) {
		if (l.tracesource.indexOf(source) != -1) {
		    l.highlightBy(source);
		    l.source.highlightBy(source);
		}
	    });
	}
    }

    graphlinks.attr("stroke-width", function (d, i) {
	if (d.isHighlighted()) {
	    return 3;
	} else {
	    return 1;
	}
    });

    graphnodes.attr("r", function (d, i) {
	return sizescale(d.highlightedBy.length);
    });
}

function reset() {
    graphlinks.attr("stroke-width", 1);
    graphlinks.style("visibility", function (d, i) {
	d.highlighted = false;
	return "visible";
    });
    graphnodes.style("visibility", function (d, i) {
	d.highlighted = false;
	return "visible";
    });
}

d3.json("out.json", function(graph, error) {
    graph.nodes.forEach(function (n) {
	nodes.push(new Highlightable(n));
    });
    
    graph.links.forEach(function (n) {
	links.push(new Highlightable(n));
    });

    var color = d3.scale.category10()

    force = d3.layout.force()
	.nodes(nodes)
	.links(links)
	.size([width,height])
	.linkStrength(2)
	.charge(-400)
	.gravity(0.35)
	.on("tick", tick)
	.start();

    // Order is important, we want to drav the circles OVER the lines, so we have
    // to add them later.
    graphlinks = sampleSVG.selectAll("line")
	.data(links).enter().append("line")
	.attr("stroke", "black")
	.attr("class", "graphlink")
	.attr("marker-end", "url(#endArrow)");

    graphnodes = sampleSVG.selectAll("circle")
	.data(nodes).enter().append("circle")
	.attr("stroke", "black")
	.attr("class", "graphnode")
	.attr("fill", function (d, i) {
	    if (d.start) {
		return color("start");
	    } else if (d.end) {
		return color("end");
	    } else {
		return color("other");
	    }
	})
	.attr("r", 5)
	.on("click",select)
	.style("z-index", 1);

    
    $(".graphnode").tipsy({
	html: true,
	gravity: $.fn.tipsy.autoWE,
	title: function() {
	    var d = this.__data__;
	    var certstring = "";
	    if (d.certificate) {
		certstring += "<span class=\"bold\">Certificate hash</span>: " + d.certificate + "<br/>";
	    }
	    if (d.fromserver) {
		certstring += "Certificate also seen by server.<br/>";
	    }
	    if (d.fromcvr) {
		certstring += "Certificate seen in CVR.<br/>";
	    }
	    return "<span class=\"bold\">IP:</span> " +
		d.id + "<br/> <span class=\"bold\">Geoinformation:</span> " +
		d.geo + "<br/> <span class=\"bold\">AS number:</span> " + d.asn + "<br/>" + certstring;
	}
    });

});
