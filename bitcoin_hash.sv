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
logic [31:0] message_buffer [0:18];  // Stores the loaded 19 words (Words 0~18)
logic [31:0] phase1_hashes [7:0];  // Stores the result of Phase 1 computed by Master
logic [31:0] intermediate_hashes [15:0][7:0];  // Stores Phase 2 results (H0-H7) for all 16 workers
logic [31:0] final_hashes [15:0];  // Stores the final H0 result for all 16 workers

// Control signals and Counters
logic [15:0] offset;  // Memory address offset
logic [4:0] i;  // General purpose index counter
logic [6:0] master_tstep;  // Counter for Master's internal SHA-256 operation (Phase 1)

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
logic [31:0] w_phase1 [0:15];  //Sliding window for Master's W expansion


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
assign msg_tail = '{message_buffer[16], message_buffer[17], message_buffer[18]};  //assign is like a forever wire connection. Here we connect message_tail to message_buffer[16~18]


// Instantiate 16 Worker modules for Phase 2 and Phase 3
genvar n;
generate
    for (n = 0; n < num_nonce; n = n + 1) begin: workers
        // Combinational Logic of Input Mux for worker_hin
        always_comb begin
            // Select input hash based on phase. create a MUX behaviorally
            if (worker_phase_sel == 0) begin
                worker_hin[n] = phase1_hashes;
            end
            else begin
                worker_hin[n] = intermediate_hashes[n];
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
        offset <= 0;
        i <= 0;
        master_tstep <= 0;
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
                    master_tstep <= 0;
                    // Prepare initial hash values for Phase 1
                    {a, b, c, d, e, f, g, h_reg} <= {initial_hashes[0], initial_hashes[1], initial_hashes[2], initial_hashes[3],
                                                    initial_hashes[4], initial_hashes[5], initial_hashes[6], initial_hashes[7]};
                    // Load first 16 words into w_phase1 for Phase 1 processing
                    w_phase1[0:15] <= message_buffer[0:15]; 
                end
            end


            PHASE1: begin
                logic [31:0] current_w;
                
                // 1.W expansion Logic
                if (master_tstep < 16) begin
                    current_w = w_phase1[master_tstep];
                end
                else begin
                    current_w = word_expan(w_phase1);
                end

                // 2.Compression logic
                if (master_tstep <64)begin
                    //A. SHA256 operation
                   {a,b,c,d,e,f,g,h_reg} <= sha256_op(a,b,c,d,e,f,g,h_reg,current_w,k[master_tstep] ); //directly input "k[master_tstep]"(the value of k at index master_tstep) into the function
                    //B. Update sliding window for W
                    if (master_tstep >= 16) begin  //only start to shift when master_tstep>15
                        for (int x=0; x<15; x++) w_phase1[x] <= w_phase1[x+1]; // shift every bit left
                        w_phase1[15] <= current_w;  //load the new current_w into the last position
                    end
                    
                    master_tstep <= master_tstep + 1;
                end
                else begin
                    // 3. Phase 1 complete, update Phase 1 hash output
                    phase1_hashes[0] <= a + initial_hashes[0];
                    phase1_hashes[1] <= b + initial_hashes[1];
                    phase1_hashes[2] <= c + initial_hashes[2];
                    phase1_hashes[3] <= d + initial_hashes[3];
                    phase1_hashes[4] <= e + initial_hashes[4];
                    phase1_hashes[5] <= f + initial_hashes[5];
                    phase1_hashes[6] <= g + initial_hashes[6];
                    phase1_hashes[7] <= h_reg + initial_hashes[7];

                    // 4. Prepare for Phase 2
                    worker_phase_sel <= 0; // Phase 2
                    worker_start <= 1;     // Start workers
                    state <= PHASE2;       // Directly go to PHASE2 to wait for workers to finish
                end        
            end


            PHASE2:begin
                if (worker_finish[0] == 1) begin // Check only worker 0's finish signal, because all workers start at the same time and have the same processing time.
                    // Collect intermediate hashes from all workers
                    for (int j=0; j<16; j=j+1) begin
                        intermediate_hashes[j] <= worker_hout[j];  // Collect all H0-H7 from each worker
                    end

                    // Prepare for Phase 3
                    worker_phase_sel <= 1; // Phase 3
                    worker_start <= 1;     // Start workers again
                    state <= PHASE3;
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
                if (i <16 )begin
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
