module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                     output logic        done, mem_clk, mem_we,
                     output logic [15:0] mem_addr,
                     output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);


parameter num_nonces = 16; // The number that we need to test the proper nonce for bitcoin hash regulation.
//parameter num_words = 19; // Bitcoin data is constructed by 20 words containing the nonce, but for the last word, we need to test it by ourselve. So we only need to load 19 words from memory.

// State definition
enum logic [4:0] {IDLE, READ, PHASE1, PHASE2, PHASE3, WRITE} state;

// Memory and Data buffers
logic [31:0] message_buffer [0:18]; 為什麼需要這個? 後面message array就在做儲存了// Stores the loaded 19 words (Words 0~18) 
logic [31:0] h_phase1 [0:7];  // Stores the result of Phase 1 computed by Master
logic [31:0] intermediate_hashes [15:0][7:0];  // Stores Phase 2 results (H0-H7) for all 16 workers
logic [31:0] final_hashes [15:0];  // Stores the final H0 result for all 16 workers

// Control signals and Counters
logic [15:0] offset;  // Memory address offset
logic [4:0] i;  // General purpose index counter

// Workers control signals (from Master to Workers)
logic worker_start;  // The start pulse for workers
logic worker_phase_sel; // 0 for Phase 2, 1 for Phase 3

// Worker inner data interface (Arrays for connecting 16 instances)
logic [31:0] worker_hin [15:0][7:0];  // Input Hash (hi) for 16 workers
logic [31:0] worker_hout [15:0][7:0];  // Output Hash (ho) for 16 workers
logic worker_finish [15:0];  // Finish signal from 16 workers
logic [31:0] msg_tail [0:2];  // Block 2 message tail (Words 16, 17, 18).  寫[0:2] 而不是 [2:0] 因為要對應順著數 i.e. word16=index0, word17=index1, word18=index2

// Master internal calculation variable for PHASE1
logic [31:0] a, b, c, d, e, f, g, h_reg;  //雖然 a, b, c, d, e, f, g 都直接用了單一字母，但唯獨 h 改成 h_reg，是因為 h 在 Verilog 語言中太過特殊（Hex 前綴）且容易與陣列名稱打架。這是一種防禦性的 Coding Style（編碼風格), 且也比較好debug 
logic [31:0] w_phase1 [0:15];  我不知道，可以刪掉// 這啥???   Sliding window for Master's W expansion


_______寫到這___


logic [31:0] hout[num_nonces];
logic [31:0] w[64];
logic [31:0] message[num_words];
logic [31:0] wt;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [ 7:0] i, tstep; // for counting purpose.
logic [31:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [63:0] bitsize;

assign num_blocks = determine_num_blocks(num_words); //Assign a register for number of blocks
assign bitsize = num_words * 32; //Assign a register for the last 64 bits of the last block.

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input integer size);

    logic [63:0] total_length; // Maximum input bits length for Bitcoin_hash.
    total_length = (size * 32) + 1 + 64; // The total length would be num of words*its size + one padding 1 + 64 size.
    determine_num_blocks = ((total_length + 511)/512); // Doing a ceiling, and other missing bits between padding 1 and size would be 0.

endfunction

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

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


// Bitcoin hash FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
    begin
    if (!reset_n) begin
        cur_we <= 1'b0;
        offset <= 0;
        state <= IDLE;
        h0 <= 32'h6a09e667;
        h1 <= 32'hbb67ae85;
        h2 <= 32'h3c6ef372;
        h3 <= 32'ha54ff53a;
        h4 <= 32'h510e527f;
        h5 <= 32'h9b05688c;
        h6 <= 32'h1f83d9ab;
        h7 <= 32'h5be0cd19;
    end 
    
    else case (state)
	 
	IDLE: begin  // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
        if(start) begin 
			i <= 0;
			tstep <= 0;
			a <= h0;
			b <= h1;
			c <= h2;
			d <= h3;
			e <= h4;
			f <= h5;
			g <= h6;
			h_reg <= h7;
			cur_we <= 0;
			offset <= 0;  //We need address and offset one cycle beyond the read process to let it load the message.
			cur_addr <= message_addr; //We need address and offset one cycle beyond the read process to let it load the message.
			
            for(int z = 0; z < 64; z++) begin
				w[z] <= 32'b0;
			end
			state <= READ;
		  end
    end

	READ: begin // Read the input message from memory.
		offset <= offset+1;
		cur_addr <= message_addr;
		if(i <= num_words) begin
			i <= i + 1;
			if (i != 0) begin
				message[i-1] <= mem_read_data; //Message need one more cycle for loading. For example, at offset = 1, the offset = 0 will be loaded.
			end
		end
		else begin
			 msg_tail[0] <= message[16];
			 msg_tail[1] <= message[17];
			 msg_tail[2] <= message[18];
		    i <= 0;
		    state <= BLOCK;
		end
	end
    

    PHASE1: begin
	 logic [31:0] current_wt;
		    if(tstep < 64) begin
			    if (tstep < 16) begin
				    current_wt = w[tstep]; // Set up a blocking statement for immediately updating message.
			    end
			 else begin
				current_wt = word_expan(tstep);
				w[tstep] <= current_wt;
		    end
			
            {a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h, current_wt, tstep);
				tstep <= tstep + 1;
		    end
		    
            else begin
                intermediate_hashes[15:0][0] <= h0 + a;
                intermediate_hashes[15:0][1] <= h1 + b;
                intermediate_hashes[15:0][2] <= h2 + c;
                intermediate_hashes[15:0][3] <= h3 + d;
                intermediate_hashes[15:0][4] <= h4 + e;
                intermediate_hashes[15:0][5] <= h5 + f;
                intermediate_hashes[15:0][6] <= h6 + g;
                intermediate_hashes[15:0][7] <= h7 + h;
                tstep <= 0;
                state <= PHASE2;
					 worker_start <= 1;  // Send Start Pulse, so when go to PHASE2, all workers can start computing immediately.
            end    
    end


    PHASE2: begin
        // Workers are running Phase 2. Wait for completion.
        // check worker_finish signals. (checking only worker[0] is sufficient since all start/finish synchronously同步發生)
        if (worker_finish[0] == 1) begin
            // Collect intermediate hashes from all workers
            for (int k=0, k<16, k=k+1) begin
                intermediate_hashes[k] <= worker_hout[k];  //在程式碼中寫下 intermediate_hashes[k] 時你指定了第一維->選定第 k 層抽屜。你沒指定第二維->這代表你指的是 「這整層抽屜裡面的所有東西」。
            end
				
            state <= PHASE3;
            worker_start <= 1;  // Send Start Pulse for Phase 3
            worker_phase_sel <= 1; // Set Phase Select to 1 for Phase 3
        end
		  else worker_start <= 0; //這個是用來防止submodule卡在idel state.
    end


    PHASE3: begin
        if (worker_finish[0] == 1) begin
            // Collect intermediate hashes from all workers
            for (int k=0, k<16, k=k+1) begin
                final_hashes[k] <= worker_hout[k][0]; // Collect only H0 from each worker  
            end

            state<=WRITE;
            i <= 0;
        end
		  else worker_start <= 0; //這個是用來防止submodule卡在idel state.
    end


    WRITE: begin

    end
    
    COMPUTE: begin
	// 64 processing rounds steps for 512-bit block 
		logic [31:0] current_wt;
		    if(tstep < 64) begin
			    if (tstep < 16) begin
				    current_wt = w[tstep]; // Set up a blocking statement for immediately updating message.
			    end
			else begin
				current_wt = word_expan(tstep);
				w[tstep] <= current_wt;
		    end
			
            {a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h, current_wt, tstep);
			tstep <= tstep + 1;
		    end
		    
            else begin
                h0 <= h0 + a;
                h1 <= h1 + b;
                h2 <= h2 + c;
                h3 <= h3 + d;
                h4 <= h4 + e;
                h5 <= h5 + f;
                h6 <= h6 + g;
                h7 <= h7 + h;
                tstep <= 0;
                state <= BLOCK;
            end
    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
		if(i < 8) begin
			offset <= i;
			cur_addr <= output_addr;
			cur_write_data <= hi[i];
			i <= i + 1;
		end
		else begin
			cur_we <= 1'b0;
			state <= IDLE;
		end
    end
    endcase
    end
// Instantiate a submodule for operating phase 2 and phase 3.
genvar nonce;
generate 
	for(nonce = 0; nonce < 16; nonce++) begin
		simpified_sha256 sha256_block(
			.clk(clk),
			.start(worker_start),
			.phase_sel(worker_phase_sel),
			.nonce(nonce),
			.hi[8](intermediate_hashes[nonce]),
			.msg_tail[0:2](msg_tail[0:2]),
			.ho[8](worker_hout[nonce]),
			.finish(worker_finish[nonce])
			);
	end
endgenerate
// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
