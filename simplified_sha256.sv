module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, start,
 input logic  phase_sel,
 input logic  [3 :0] nonce,
 input logic  [31:0] hi[8],
 input logic  [31:0] msg_tail [0:2],
 output logic [31:0] ho[8],
 output logic finish
 );

// FSM state variables 
enum logic [2:0] { PHASE2, PHASE3, OUTPUT} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[64];
logic [31:0] a, b, c, d, e, f, g, h;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [ 7:0] tstep;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};




// SHA256 hash round.
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [ 7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^(a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction
//Word expansion before doing SHA256 hash round.
function logic [31:0] word_expan(input logic [ 7:0] t);
	 logic [31:0] s0,s1;
begin
	 s0 = (rightrotate(w[t-15], 7)) ^ (rightrotate(w[t-15], 18)) ^ (rightshift(w[t-15], 3));
	 s1 = (rightrotate(w[t-2], 17)) ^ (rightrotate(w[t-2], 19)) ^ (rightshift(w[t-2], 10));
	 word_expan = w[t-16] + s0 + w[t-7] + s1;
end
endfunction


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction
//Right shift function for word expansion.
function logic [31:0] rightshift(input logic [31:0] x,
											input logic [ 7:0] r);
	rightshift = (x >> r);
endfunction

// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory

always_ff @(posedge clk)
begin
	if (start) begin
      tstep <= 0;
		a <= hi[0];
		b <= hi[1];
		c <= hi[2];
		d <= hi[3];
		e <= hi[4];
		f <= hi[5];
		g <= hi[6];
		h <= hi[7];
		finish <= 0;
		if(phase_sel == 0) begin
		state <= PHASE2;
		end
		else begin
		state <= PHASE3;
		end
	end
	else begin
		case (state)
		PHASE2: begin
	// 64 processing rounds steps for 512-bit block 
			logic [31:0] current_wt;
			if(tstep < 64) begin
				if (tstep < 3) begin
					current_wt = msg_tail[tstep]; // Set up a blocking statement for immediately updating message.
					w[tstep] <= msg_tail[tstep];
				end
				else if(tstep == 3) begin
					current_wt = nonce;
					w[tstep] <= nonce;
					
				end
				else if(tstep == 4) begin
					current_wt = 32'h80000000;
					w[tstep] <= 32'h80000000;
				end
				else if(tstep < 15) begin
					current_wt = 32'h00000000;
					w[tstep] <= 32'h00000000;
				end
				else if(tstep == 15) begin
					current_wt = 32'd640;
					w[tstep] <= 32'd640;
				end
				else begin
					current_wt = word_expan(tstep);
					w[tstep] <= current_wt;
				end
				{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h, current_wt, tstep);
				tstep <= tstep + 1;
			end
			else begin
				h0 <= hi[0] + a;
				h1 <= hi[1] + b;
				h2 <= hi[2] + c;
				h3 <= hi[3] + d;
				h4 <= hi[4] + e;
				h5 <= hi[5] + f;
				h6 <= hi[6] + g;
				h7 <= hi[7] + h;
				tstep <= 0;
				state <= OUTPUT;
			end
		end
		PHASE3: begin
	// 64 processing rounds steps for 512-bit block 
			logic [31:0] current_wt;
			if(tstep < 64) begin
				if (tstep < 8) begin
					current_wt = hi[tstep]; // Set up a blocking statement for immediately updating message.
					w[tstep] <= hi[tstep];
				end
				else if (tstep == 8) begin
					current_wt = 32'h80000000;
					w[tstep] <= 32'h80000000;
				end
				else if (tstep < 15) begin
					current_wt = 32'h00000000;
					w[tstep] <= 32'h00000000;
				end
				else if (tstep == 15) begin
					current_wt = 32'd256;
					w[tstep] <= 32'd256;
				end
				else begin
					current_wt = word_expan(tstep);
					w[tstep] <= current_wt;
				end
				{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h, current_wt, tstep);
				tstep <= tstep + 1;
			end
			else begin
				h0 <= hi[0] + a;
				h1 <= hi[1] + b;
				h2 <= hi[2] + c;
				h3 <= hi[3] + d;
				h4 <= hi[4] + e;
				h5 <= hi[5] + f;
				h6 <= hi[6] + g;
				h7 <= hi[7] + h;
				tstep <= 0;
				state <= OUTPUT;
			end
		end
		OUTPUT: begin
			ho[0] <= h0;
			ho[1] <= h1;
			ho[2] <= h2;
			ho[3] <= h3;
			ho[4] <= h4;
			ho[5] <= h5;
			ho[6] <= h6;
			ho[7] <= h7;
			finish <= 1;
		end
		default: begin
			finish <= 0;
		end
   endcase
  end
end
endmodule
