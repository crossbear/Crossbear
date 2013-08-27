/*
  First draw malicious traces (without certificate that has been
  confirmed by the server), then draw all non-malicious traces
  intersecting a malicious trace.
*/

var width = window.innerWidth;
var height = window.innerHeight;
var sampleSVG = d3.select("#viz")
    .append("svg")
    .attr("xmlns", "http://www.w3.org/2000/svg")
    .attr("version", "1.1")
    .attr("width", width)
    .attr("height", height);

var linkscale = d3.scale.linear().domain([0,1,5]).range([1, 3, 8]).clamp(true);

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
	if (d.highlightedBy.length > 0) {
	    // deselect trace
	    links.forEach(function (l) {
		var index = l.highlightedBy.indexOf(source);
		if (index != -1) {
		    l.highlightedBy.splice(index, 1);
		}
		index = l.source.highlightedBy.indexOf(source);
		if (index != -1) {
		    l.source.highlightedBy.splice(index, 1);
		}
	    });
	} else {
	    // select trace
	    links.forEach(function (l) {
		if (l.tracesource.indexOf(source) != -1) {
		    l.highlightedBy.push(source);
		    l.source.highlightedBy.push(source);
		}
	    });
	}
    }

    graphlinks.attr("stroke-width", function (d, i) {
	return linkscale(d.highlightedBy.length);
    });

    graphnodes.attr("stroke-width", function (d, i) {
	return linkscale(d.highlightedBy.length);
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

function hideselected() {
    graphlinks.style("visibility", function (d, i) {
	if (d.highlighted) {
	    return "hidden";
	}
    });
    graphnodes.style("visibility", function (d, i) {
	if (d.highlighted) {
	    return "hidden";
	}
    });
}


d3.json("out.json", function(graph, error) {
    nodes = graph.nodes;
    links = graph.links;

    nodes.forEach(function (d) {
	d.highlightedBy = [];
    });

    links.forEach(function (d) {
	d.highlightedBy = [];
    });
    
    var color = d3.scale.category10()

    force = d3.layout.force()
	.nodes(nodes)
	.links(links)
	.size([width,height])
	.linkStrength(2)
	.charge(-400)
	.gravity(0.3)
	.on("tick", tick)
	.start();

    sampleSVG.append("rect")
	.attr("height", 50)
	.attr("width", 100)
	.attr("x", 10)
	.attr("y", 10)
	.attr("fill", "white")
	.attr("stroke", "black")
	.attr("stroke-width", 2)
	.on("click", reset);

    sampleSVG.append("rect")
	.attr("height", 50)
	.attr("width", 100)
	.attr("x", 10)
	.attr("y", 70)
	.attr("fill", "white")
	.attr("stroke", "black")
	.attr("stroke-width", 2)
	.on("click", hideselected);


    sampleSVG.append("text")
	.text("Reset")
	.attr("x", 20)
	.attr("y", 35)
	.attr("dy", "0.25em")
	.on("click", reset);

    sampleSVG.append("text")
	.text("Hide selected")
	.attr("x", 20)
	.attr("y", 85)
	.attr("dy", "0.25em")
	.on("click", hideselected);


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
