module flipflop_synchronizer
#(parameter integer WIDTH=1, parameter integer NUM_OF_STAGES=2) //NUM_OF_STAGES=2: Defaults to using a 2-stage register chain
(
  input logic clock, reset, 
  input logic [WIDTH-1:0] d,
  output logic [WIDTH-1:0] q
);

 logic[WIDTH-1:0] r[NUM_OF_STAGES-1:0];  //Unpacked Array, declares 'NUM_OF_STAGES' registers, where every register has a width of 'WIDTH'
                                         //represents the core structure of the synchronizer: a chain of connected Flip-Flops.
 

 always_ff@(posedge clock, posedge reset) begin
	  if(reset == 1) begin
		  for(int i=0; i<NUM_OF_STAGES; i=i+1) begin
		    r[i] <= 0;  //When Reset occurs, clear every Flip-Flop in this register chain to 0
		  end
	  end
	  
	  else begin
		 r[0] <= d;
		 for(int i=0; i<(NUM_OF_STAGES-1); i=i+1) begin
			r[i+1] <= r[i];
		 end
	  end
 end
	 
 assign q = (reset == 0) ? r[NUM_OF_STAGES-1] : 0;  

 endmodule: flipflop_synchronizer