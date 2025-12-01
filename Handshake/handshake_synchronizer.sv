module handshake_synchronizer(
  input logic start, 
  output logic ready,
  input logic[31:0] data_in,
  output logic [31:0] data_out,
  input src_clk, dest_clk,
  input src_reset, dest_reset
);

// local variables
logic [31:0] data_in_reg, data;
logic data_out_en, data_in_en;
logic req_o, ack_o, sync_req_i, sync_ack_i;


//對應左上角的 fast src_clk domain 32-bit register
// input data register (register input data_in to data_in_reg)
always_ff@(posedge src_clk, posedge src_reset) begin
	if(src_reset == 1)begin
		data_in_reg <= 32'b0;
	end
	else if(data_out_en == 1)begin
		data_in_reg <= data_in;
	end
end

// 對應 Data Latch :
// Control sending data from input data register through data latch
assign data = (data_out_en==1) ? data_in_reg : data;  //if data_out_en== 0 -> remain the previous value

//對應右上角的 slow dest_clk domain 32-bit register
// output data register (destination register to load data sent by sender_fsm)
always_ff@(posedge dest_clk, posedge dest_reset) begin
	if(dest_reset == 1)begin
		data_out <= 32'b0;
	end
	else if(data_in_en == 1)begin
		data_out <= data;
	end
end


// Sender handshake synchronizer FSM instance
// Note : connect req_o to req_o and ack_i to sync_ack_i
sender_fsm sender_fsm_inst(
	.start(start), 
	.ready(ready), 
	.data_out_en(data_out_en), 
	.req_o(req_o), 
	.ack_i(sync_ack_i),
	.src_clk(src_clk),
	.src_reset(src_reset)
);

// Receiver handshake synchronizer FSM instance
// Note : connect req_i to sync_req_i and ack_o to ack_o
receiver_fsm receiver_fsm_inst(
	.data_in_en(data_in_en), 
	.req_i(sync_req_i), 
	.ack_o(ack_o),
	.dest_clk(dest_clk),
	.dest_reset(dest_reset)
);

// 2ff synchronizer instance for ack_o coming from receiver_fsm
// output of this synchronizer sync_ack_i will be connected to sender_fsm instance ack port
flipflop_synchronizer #(.WIDTH(1), .NUM_OF_STAGES(2)) ack_2ff_sync_inst 
(
	.d(ack_o),
	.q(sync_ack_i),
	.clock(src_clk),
	.reset(src_reset)
);

// 2ff synchronizer instance for req_o coming from sender_fsm
// output of this synchronizer sync_req_i will be connected to receiver_fsm instance ack_i port
flipflop_synchronizer #(.WIDTH(1), .NUM_OF_STAGES(2)) req_2ff_sync_inst 
(
	.d(req_o),
	.q(sync_req_i),
	.clock(dest_clk),
   .reset(dest_reset)

);

endmodule : handshake_synchronizer
