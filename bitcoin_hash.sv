module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                     output logic        done, mem_clk, mem_we,
                     output logic [15:0] mem_addr,
                     output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);


parameter num_nonce = 16; // The number that we need to test the proper nonce for bitcoin hash regulation.
//parameter num_words = 19; // Bitcoin data is constructed by 20 words containing the nonce, but for the last word, we need to test it by ourselve. So we only need to load 19 words from memory.

// State definition
enum logic [4:0] {IDLE, READ, PHASE1, PHASE2, PHASE3, WRITE} state;

// Memory and Data buffers
logic [31:0] msg_tail[3];
logic [31:0] message_buffer [0:18];  // Stores the loaded 19 words (Words 0~18)
logic [31:0] phase1_hashes [7:0];  // Stores the result of Phase 1 computed by Master
logic [31:0] final_hashes [15:0];  // Stores the final H0 result for all 16 workers

// Control signals and Counters
logic [15:0] offset;  // Memory address offset
logic [4:0] i;  // General purpose index counter
logic [6:0] tstep;  // Counter for Master's internal SHA-256 operation (Phase 1)

// Master internal calculation variable for PHASE1
logic [31:0] a[16], b[16], c[16], d[16], e[16], f[16], g[16], h_reg[16];  //雖然 a, b, c, d, e, f, g 都直接用了單一字母，但唯獨 h 改成 h_reg，是因為 h 在 Verilog 語言中太過特殊（Hex 前綴）且容易與陣列名稱打架。這是一種防禦性的 Coding Style（編碼風格), 且也比較好debug 
logic [31:0] a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1;
logic [31:0] w[15:0];  //Sliding window for Master's W expansion
logic [31:0] wt[15:0][15:0];


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


//Function declarations for Phase 1

//Word expansion function using Sliding window method
function logic [31:0] word_expan (input logic [31:0]w_arr[0:15]);  //w_arr 代表0~15的座位,跟SHA256中 w 代表實際數字本身不一樣
    logic [31:0] s0,s1;
    
    s0 = (rightrotate(w_arr[1], 7)) ^ (rightrotate(w_arr[1], 18)) ^ (rightshift(w_arr[1], 3));
	s1 = (rightrotate(w_arr[14], 17)) ^ (rightrotate(w_arr[14], 19)) ^ (rightshift(w_arr[14], 10));
    word_expan = w_arr[0] + s0 + w_arr[9] + s1;
endfunction

// SHA-256 Compression Function
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, k_val);  // 呼叫者必須先把 k[t] 查好，傳入具體的數值 (32-bit)
    logic [31:0] S1, S0, ch, maj, t1, t2;
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k_val + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
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


// Memory interface logic
assign mem_clk = clk;
assign mem_addr = (state == READ) ? (message_addr + offset) : (output_addr + offset);  // Address Selection: Read from message_addr, Write to output_addr
assign mem_we = (state == WRITE) ? 1'b1 : 1'b0;
 
//Prepare common message tail (Words 16, 17, 18) for Block 2
assign msg_tail[0] = message_buffer[16];  //assign is like a forever wire connection. Here we connect message_tail to message_buffer[16~18]
assign msg_tail[1] = message_buffer[17];
assign msg_tail[2] = message_buffer[18];


always_ff @(posedge clk, negedge reset_n)begin
    if (!reset_n) begin
        state <= IDLE;
        done <=0;
        offset <= 0;
        i <= 0;
        tstep <= 0;
    end
    else begin
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
                    i <= i + 1; 
                end
                /*
                First cycle offset=0, just set up address
                Second cycle offset=1, load word0 to message_buffer[0], i=0->1
                Third cycle offset=2, load word1 to message_buffer[1], i= 1->2
                */
                
                //Transition to Phase 1 when reading is complete
                if ( i == 19 )begin
                    state <= PHASE1;
                    tstep <= 0;
                    // Prepare initial hash values for Phase 1
						  {a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1} <= {initial_hashes[0], initial_hashes[1], initial_hashes[2], initial_hashes[3],
                                                    initial_hashes[4], initial_hashes[5], initial_hashes[6], initial_hashes[7]};
                    // Load first 16 words into w_phase1 for Phase 1 processing
                    for (int k = 0; k < 16; k++ ) begin 
							w[k] <= message_buffer[k]; 
						  end
                end
            end


            PHASE1: begin
                logic [31:0] current_w;
                
                // 1.W expansion Logic
                if (tstep < 16) begin
                    current_w = w[tstep];
                end
                else begin
                    current_w = word_expan(w);
                end

                // 2.Compression logic
                if (tstep < 64)begin
                    //A. SHA256 operation
                   {a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1} <= sha256_op(a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1,current_w,k[tstep] ); //directly input "k[master_tstep]"(the value of k at index master_tstep) into the function
                    //B. Update sliding window for W
                    if (tstep >= 16) begin  //only start to shift when master_tstep>15
                        for (int x=0; x < 15; x++) begin
									w[x] <= w[x+1]; // shift every bit left
								end
                        w[15] <= current_w;  //load the new current_w into the last position
                    end
                    
                    tstep <= tstep + 1;
                end
                else begin
                    // 3. Phase 1 complete, update Phase 1 hash output
                    phase1_hashes[0] <= a_phase1 + initial_hashes[0];
                    phase1_hashes[1] <= b_phase1 + initial_hashes[1];
                    phase1_hashes[2] <= c_phase1 + initial_hashes[2];
                    phase1_hashes[3] <= d_phase1 + initial_hashes[3];
                    phase1_hashes[4] <= e_phase1 + initial_hashes[4];
                    phase1_hashes[5] <= f_phase1 + initial_hashes[5];
                    phase1_hashes[6] <= g_phase1 + initial_hashes[6];
                    phase1_hashes[7] <= h_phase1 + initial_hashes[7];
						  
						  for (int k = 0; k < 16; k++) begin
                        a[k] <= a_phase1 + initial_hashes[0]; // 直接拿上面的運算結果載入
                        b[k] <= b_phase1 + initial_hashes[1];
                        c[k] <= c_phase1 + initial_hashes[2];
                        d[k] <= d_phase1 + initial_hashes[3];
                        e[k] <= e_phase1 + initial_hashes[4];
                        f[k] <= f_phase1 + initial_hashes[5];
                        g[k] <= g_phase1 + initial_hashes[6];
                        h_reg[k] <= h_phase1 + initial_hashes[7];
                    end
                    state <= PHASE2;       // Directly go to PHASE2 to wait for workers to finish
						  tstep <= 0;
                end        
            end


            PHASE2:begin
						 for (int k=0; k < num_nonce; k++) begin
                        logic [31:0] current_wt; 
                   
                        if (tstep < 3)       current_wt = msg_tail[tstep];
                        else if (tstep == 3) current_wt = k; // 【重點】這裡帶入 Nonce！ k 就是 nonce 值 (0~15)
                        else if (tstep == 4) current_wt = 32'h80000000;
                        else if (tstep < 15) current_wt = 32'd0;
                        else if (tstep == 15) current_wt = 32'd640;
                        else                 current_wt = word_expan(wt[k]); // 使用第 k 個人的 w

                        // 2. 更新 Sliding Window (第 k 個人的)
                        if (tstep < 64) begin
                            if (tstep < 16) wt[k][tstep] <= current_wt;
                            else begin
                                for (int x=0; x<15; x++) wt[k][x] <= wt[k][x+1];
                                wt[k][15] <= current_wt;
                            end

                            // 3. 執行 SHA256 Function (大家共用同一個 function 但輸入不同)
                            {a[k], b[k], c[k], d[k], e[k], f[k], g[k], h_reg[k]} <= sha256_op(a[k], b[k], c[k], d[k], e[k], f[k], g[k], h_reg[k], current_wt, k[tstep]);
                        end
                    end // End of FOR LOOP

                    // 控制計數器 (只有一個，控制所有人)
                    if (tstep < 64) tstep <= tstep + 1;
                    else begin
                        // 結算
                        for (int k = 0; k < 16; k++) begin
									wt[k][0] <= a[k] + phase1_hashes[0];
									wt[k][1] <= b[k] + phase1_hashes[1];
									wt[k][2] <= c[k] + phase1_hashes[2];
									wt[k][3] <= d[k] + phase1_hashes[3];
									wt[k][4] <= e[k] + phase1_hashes[4];
									wt[k][5] <= f[k] + phase1_hashes[5];
									wt[k][6] <= g[k] + phase1_hashes[6];
									wt[k][7] <= h_reg[k] + phase1_hashes[7];

                        // 2. 重置 a~h 為 SHA-256 標準 IV (為了 Phase 3 的運算)
                        //    這步非常重要！因為 sha256_op 需要從這些初始值開始算
									a[k] <= 32'h6a09e667; 
									b[k] <= 32'hbb67ae85; 
									c[k] <= 32'h3c6ef372; 
									d[k] <= 32'ha54ff53a;
									e[k] <= 32'h510e527f; 
									f[k] <= 32'h9b05688c; 
									g[k] <= 32'h1f83d9ab; 
									h_reg[k] <= 32'h5be0cd19;
								end
                        state <= PHASE3;
                        tstep <= 0;
                    end
				end
				
				PHASE3: begin
						  for (int k=0; k < num_nonce; k++) begin
                        logic [31:0] current_wt; 
                        
                        if (tstep < 8) current_wt = wt[k][tstep]; // Set up a blocking statement for immediately updating message.
								else if (tstep == 8) current_wt = 32'h80000000;
								else if (tstep < 15) current_wt = 32'h00000000;
								else if (tstep == 15) current_wt = 32'd256;
								else current_wt = word_expan(wt[k]);
                        // 2. 更新 Sliding Window (第 k 個人的)
                        if (tstep < 64) begin
                            if (tstep < 16) wt[k][tstep] <= current_wt;
                            else begin
                                for (int x=0; x<15; x++) wt[k][x] <= wt[k][x+1];
                                wt[k][15] <= current_wt;
                            end

                            // 3. 執行 SHA256 Function (大家共用同一個 function 但輸入不同)
                            {a[k], b[k], c[k], d[k], e[k], f[k], g[k], h_reg[k]} <= sha256_op(a[k], b[k], c[k], d[k], e[k], f[k], g[k], h_reg[k], current_wt, k[tstep]);
                        end
                    end // End of FOR LOOP

                    // 控制計數器 (只有一個，控制所有人)
                    if (tstep < 64) tstep <= tstep + 1;
                    else begin
                        // 結算
                        for (int k=0; k<16; k++) begin
                             final_hashes[k] <= 32'h6a09e667 + a[k];
                        end
                        state <= WRITE;
                        tstep <= 0;
                    end
            end
            WRITE: begin
                if (i < 16 )begin
                    offset <= i;
                    mem_write_data <= final_hashes[i]; //When i=0, write final_hashes[0] (ie. H0), to memory ; i=1, write H1; ... i=7, write H7
                    i <= i + 1;
                end
                else begin
                    done <= 1;
                    state <= IDLE;
                end
            end
        
        endcase
    end
end

endmodule
