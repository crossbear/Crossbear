var width = 1440;
var height = 900;
var sampleSVG = d3.select("#viz")
    .append("svg")
    .attr("width", width)
    .attr("height", height);

var force, nodes = [] , links = [], graphnodes = [], graphlinks = []

function tick(e) {
    graphnodes.attr("cx", function(d) {
	if (d.start) {
	    d.x = d.x - e.alpha * 100;
	}
	if (d.end) {
	    d.x = d.x + e.alpha * 200;
	}
	return d.x;
	})
	.attr("cy", function(d) { return d.y; })
	.attr("fill", function (d) {
	    if (d.start) {
		return "#00ff00";
	    } else if (d.end) {
		return "#ff0000";
	    }});
    graphlinks.attr("x1", function(d) { return d.source.x; })
	.attr("x2", function(d) { return d.target.x; })
	.attr("y1", function(d) { return d.source.y; })
	.attr("y2", function(d) { return d.target.y; });
};

d3.json("out.json", function(graph, error) {
    nodes = graph.nodes;
    links = graph.links;

    force = d3.layout.force()
	.nodes(nodes)
	.links(links)
	.size([width,height])
	.linkStrength(0.9)
	.charge(-100)
	.gravity(0.09)
	.on("tick", tick)
	.start();
    
    graphnodes = sampleSVG.selectAll("circle")
	.data(nodes).enter().append("circle")
	.attr("stroke", "black")
	.attr("class", "graphnode")
	.attr("r", 5);

    
    graphlinks = sampleSVG.selectAll("line")
	.data(links).enter().append("line")
	.attr("stroke", "black")
	.attr("class", "graphlink");

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
