var sampleSVG = d3.select("#viz")
    .append("svg")
    .attr("width", 500)
    .attr("height", 500);

var force, nodes = [] , links = [];

function tick() {
    sampleSVG.selectAll(".graphnode")
    	.attr("cx", function(d) { return d.x; })
	.attr("cy", function(d) { return d.y; });
    sampleSVG.selectAll(".graphlink")
	.attr("x1", function(d) { return d.source.x; })
	.attr("x2", function(d) { return d.target.x; })
	.attr("y1", function(d) { return d.source.y; })
	.attr("y2", function(d) { return d.target.y; });
    
};

d3.json("test.json", function(graph, error) {
    nodes = graph.nodes;
    links = graph.links;
    force = d3.layout.force()
	.linkDistance(10)
	.nodes(nodes)
	.links(links)
	.size([500,500])
	.charge(-120)
	.on("tick", tick)
	.start();
    
    sampleSVG.selectAll("circle")
	.data(nodes).enter().append("circle")
	.attr("stroke", "black")
	.attr("class", "graphnode")
	.attr("r", 5);
    
    sampleSVG.selectAll("line")
	.data(links).enter().append("line")
	.attr("stroke", "black")
	.attr("class", "graphlink");

    $(".graphnode").tipsy({
	html: true,
	gravity: 'e',
	title: function() {
	    var d = this.__data__;
	    return d.geo + "<br/>" + d.asn;
	}
    });

});
