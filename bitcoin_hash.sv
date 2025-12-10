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
logic [31:0] message_buffer [0:18];  // Stores the loaded 19 words (Words 0~18)
logic [31:0] phase1_hashes [0:7];  // Stores the result of Phase 1 computed by Master
logic [31:0] intermediate_hashes [15:0][7:0];  // Stores Phase 2 results (H0-H7) for all 16 workers
logic [31:0] final_hashes [15:0];  // Stores the final H0 result for all 16 workers

// Control signals and Counters
logic [15:0] offset;  // Memory address offset
logic [4:0] i;  // General purpose index counter
logic [6:0] master_step;  // Counter for Master's internal SHA-256 operation (Phase 1)

// Workers control signals (from Master to Workers)
logic worker_start;  // The start pulse for workers
logic worker_phase_sel; // 0 for Phase 2, 1 for Phase 3

// Worker inner data interface (Arrays for connecting 16 instances)
logic [31:0] worker_hin [15:0][7:0];  // Input Hash (hi) for 16 workers
logic [31:0] msg_tail [0:2];  // Block 2 message tail (Words 16, 17, 18).  寫[0:2] 而不是 [2:0] 因為要對應順著數 i.e. word16=index0, word17=index1, word18=index2
logic worker_finish [15:0];  // Finish signal from 16 workers
logic [31:0] worker_hout [15:0][7:0];  // Output Hash (ho) for 16 workers

// Master internal calculation variable for PHASE1
logic [31:0] a, b, c, d, e, f, g, h_reg;  //雖然 a, b, c, d, e, f, g 都直接用了單一字母，但唯獨 h 改成 h_reg，是因為 h 在 Verilog 語言中太過特殊（Hex 前綴）且容易與陣列名稱打架。這是一種防禦性的 Coding Style（編碼風格), 且也比較好debug 
logic [31:0] w_phase1 [0:15];  // 這啥???  Sliding window for Master's W expansion


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

// Initial Hash Values (H0 to H7)
parameter logic [31:0] initial_hashes[0:7] = '{
    32'h6a09e667,
    32'hbb67ae85,
    32'h3c6ef372,
    32'ha54ff53a,
    32'h510e527f,
    32'h9b05688c,
    32'h1f83d9ab,
    32'h5be0cd19
};


// Memory interface logic
assign mem_clk = clk;
assign mem_addr = (state == READ) ? (message_addr + offset) : (output_addr + offset);  // Address Selection: Read from message_addr, Write to output_addr
assign mem_we = (state == WRITE) ? 1'b1 : 1'b0;
assign mem_write_data = final_hashes[i];  //When i=0, write final_hashes[0] (ie. H0), to memory ; i=1, write H1; ... i=7, write H7
//Prepare common message tail (Words 16, 17, 18) for Block 2
assign message_tail = '{message_buffer[16], message_buffer[17], message_buffer[18]};  //assign is like a forever wire connection. Here we connect message_tail to message_buffer[16~18]


// Instantiate 16 Worker modules for Phase 2 and Phase 3
genvar n;
generate
    for (n = 0; n < num_nonce; n = n + 1) begin: workers
        // Combinational Logic of Input Mux for worker_hin
        always_comb begin
            // Select input hash based on phase. create a MUX behaviorally
            if (worker_phase_sel == 0) begin
                worker_hin[n] <= phase1_hashes;
            end
            else begin
                worker_hin[n] <= intermediate_hashes;
            end
        end
        //Instantiate Worker module
        sha256_worker worker_inst (
            .clk(clk),
            .start(worker_start),
            .phase_sel(worker_phase_sel),
            .nonce(n[3:0]),  //only need the 4 LSB bits of n(0 to 15). n=0(nonce=0)->nonce=0 input to worker1 ; n=1(nonce=1)->nonce=1 input to worker2
            .hi(worker_hin[n]),  // When n=0, worker_hin[0] goes to the first worker ; n=1, worker_hin[1] goes to second worker
            .msg_tail(msg_tail),
            .ho(worker_hout[n]),
            .finish(worker_finish[n])
        );       
    end
endgenerate
/*
在 generate區塊中直接寫 if，這叫做 Generate If。 它的判斷是在 「晶片還沒做出來之前 (編譯/合成時)」 進行的
邏輯是： 編譯器會看這個條件，如果是真，就把牆壁蓋在左邊；如果是假，就把牆壁蓋在右邊
條件必須是 「常數 (Parameter/Genvar)」。也就是說，在蓋房子的時候就必須決定好，蓋好之後就 不能動了
但 worker_phase_sel 是個會變動的signal (在run time會變0 or 1決定為Phase2 or 3)
所以要加always_comb 當作Run Time時的切換開關(由內部if else 生成 MUX) 不能只用 generate 然後接 if
*/
/*
為什麼不直接寫 .nonce(n) ?
n 是什麼？ n 是一個 genvar (Generate Variable)。在 SystemVerilog 中，genvar 在運算過程中通常被視為一個 32-bit 的整數 (Integer)。
Worker 的接口是什麼？ 你的 sha256_worker 模組裡面，nonce 這個 Input Port 被定義為： input logic [3:0] nonce
如果寫 .nonce(n) 會發生什麼事？ 你試圖把一個 32-bit 的整數 (n) 塞進一個 4-bit 的接口 (nonce)。 這會導致位元寬度不匹配 (Bit-Width Mismatch) 的問題，可能會引發合成錯誤或警告。
*/


always_ff @(posedge clk, negedge reset_n)begin
    if (!reset_n) begin
        state <= IDLE;
        done <=0;
        mem_we <= 0;
        offset <= 0
        i <= 0;
        master_step <= 0;
        worker_start <= 0;
        worker_phase_sel <= 0;
    end
    else begin
        // Clear start pulse after one cycle. If don't clear, the workers will keep restarting and always stuck at tstep=0.
        if (worker_start) begin
            worker_start <= 0;  
        end
        
        case(state)
            IDLE: begin
                done <= 0;
                if (start) begin 
                    // Initialize variables and prepare to read message
                    offset <= 0;
                    i <= 0;
                    state <= READ;   
               end
            end


            READ: begin
                if (offset < 19) offset <= offset + 1;

                if (offset > 0 && i < 19)begin
                    message_buffer[i] <= mem_read_data;  // CANNOT USE "FOR" LOOP HERE BECAUSE reading from memory is sequential, not parallel. If we use for loop, it means reading all 19 words at the same time.
                    i = i + 1; 
                end
                /*
                First cycle offset=0, just set up address
                Second cycle offset=1, load word0 to message_buffer[0], i=0->1
                Third cycle offset=2, load word1 to message_buffer[1], i= 1->2
                */
                
                //Transition to Phase 1 when reading is complete
                if ( i == 19 )begin
                    state <= PHASE1;
                    master_step <= 0;
                    // Prepare initial hash values for Phase 1
                    {a, b, c, d, e, f, g, h_reg} <= {initial_hashes[0], initial_hashes[1], initial_hashes[2], initial_hashes[3],
                                                    initial_hashes[4], initial_hashes[5], initial_hashes[6], initial_hashes[7]};
                    // Load first 16 words into w_phase1 for Phase 1 processing
                    w_phase1[0:15] <= message_buffer[0:15]; 
                end
            end


            PHASE1: begin
            
            state <= PHASE2;
            worker_start <= 1;   // Send Start Pulse for Phase 2
            worker_phase_sel <= 0;  // Set Phase Select to 0 for Phase 2
            end   


            PHASE2: begin
                // Workers are running Phase 2 (64 cycles). Wait for completion.
                // check worker_finish signals. (checking only worker[0] is sufficient since all start/finish synchronously同步發生)
                if (worker_finish[0] == 1) begin
                    // Collect intermediate hashes from all workers
                    for (int j=0; j<16; j=j+1) begin
                        intermediate_hashes[j] <= worker_hout[j];  //在程式碼中寫下 intermediate_hashes[k] 時你指定了第一維->選定第 k 層抽屜。你沒指定第二維->這代表你指的是 「這整層抽屜裡面的所有東西」。
                    end
                    
                    state <= PHASE3;
                    worker_start <= 1;  // Send Start Pulse for Phase 3
                    worker_phase_sel <= 1; // Set Phase Select to 1 for Phase 3
                end
            end


            PHASE3: begin
                if (worker_finish[0] == 1) begin
                    // Collect intermediate hashes from all workers
                    for (int j=0; j<16; j=j+1) begin
                        final_hashes[j] <= worker_hout[j][0]; // Collect only H0 from each worker  
                    end

                    state<=WRITE;
                    offset <= 0;  // Reset offset for WRITE stage. bc we already used offset in READ stage (offset=19), if not reset, the offset value will start from 19 in WRITE stage.
                    i <= 0;     // Reset i for WRITE stage (also used in READ stage)
                end
            end


            WRITE: begin

            end
        
        endcase
    end
end
endmodule

_______寫到這___







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
			j <= 0;
			tstep <= 0;
			a <= h0;
			b <= h1;
			c <= h2;
			d <= h3;
			e <= h4;
			f <= h5;
			g <= h6;
			h <= h7;
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
		    i <= 0;
		    state <= BLOCK;
		end
	end
    

    PHASE1: begin


    worker_start <= 1;  // Send Start Pulse, so when go to PHASE2, all workers can start computing immediately.    
    end


   
    
    
    
    











    
    
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation
	if (j == num_blocks) begin // Detecting whether the process is finished. If so, then go to write process.
		hi[0] <= h0; 
		hi[1] <= h1; 
		hi[2] <= h2; 
		hi[3] <= h3;
		hi[4] <= h4; 
		hi[5] <= h5; 
		hi[6] <= h6; 
		hi[7] <= h7;
		i <= 0;           
		cur_we <= 1'b1;
		state <= WRITE;
	end
    else begin
        for (int k = 0; k < 16; k++) begin // 16 message a run.
            int cur_i;
            cur_i = 16 * j + k; //Global counter for counting which position should start.
				
            if ((j == num_blocks - 1) && (k >= 14)) begin // Detect for the last two message of the message size.
                if (k == 14) w[k] <= bitsize[63:32];
                if (k == 15) w[k] <= bitsize[31:0];
            end
            
            else if (cur_i < num_words) begin // Detect for the messaages that are not loaded. 
                w[k] <= message[cur_i];
            end
            
            else if (cur_i == num_words) begin 
                w[k] <= nonce;
					 nonce <= nonce + 1; // Testing different nonce from 0 to 15.
            end
            else if (cur_i == num_words + 1) begin// Detect for the 1 padding after the input message.
					 w[k] <= 32'h80000000;
				end
            else begin // Else are 32-bit 0 padding.
                w[k] <= 32'b0;
            end
        end 

        tstep <= 0; 
        a <= h0; 
		b <= h1; 
		c <= h2; 
		d <= h3;
        e <= h4; 
		f <= h5; 
		g <= h6; 
		h <= h7; // Before every operation, the a to h value should update to the previos hash value.
        state <= COMPUTE;
    end
	end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
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
                j  <= j + 1;
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

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
