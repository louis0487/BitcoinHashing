module bitcoin_hash (
    input  logic        clk, reset_n, start,
    input  logic [15:0] message_addr, output_addr,
    output logic        done, mem_clk, mem_we,
    output logic [15:0] mem_addr,
    output logic [31:0] mem_write_data,
    input  logic [31:0] mem_read_data
);

parameter num_nonce = 16; // number of nonces (0..15)

// State definition
enum logic [4:0] {IDLE, READ, PHASE1, PHASE2, PHASE2_P2, PHASE3, PHASE3_P2, WRITE} state;
enum logic [4:0] {IDLE, READ, PHASE1, PHASE2, PHASE3, WRITE} state;

// Memory and Data buffers
logic [31:0] msg_tail[3];
logic [31:0] message_buffer [0:18];  // Stores the loaded 19 words (Words 0~18)
logic [31:0] phase1_hashes [7:0];  // Stores the result of Phase 1 computed by Master
logic [31:0] final_hashes [15:0];  // Stores the final H0 result for all 16 workers

// Control signals and Counters
logic [15:0] offset;  // Memory address offset
logic [4:0] i;  // General purpose index counter
logic [6:0] tstep;  // Counter for internal SHA-256 rounds (0..63)
logic group_sel;    // Selects which group of 8 nonces to process

// Master internal calculation variable for PHASE1
logic [31:0] a[16], b[16], c[16], d[16], e[16], f[16], g[16], h_reg[16];
logic [31:0] a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1;
logic [31:0] w[15:0];  // Sliding window for Master's W expansion
logic [31:0] wt[15:0][15:0]; // wt[n][t] per-nonce schedule buffer (0..15)

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

// Function declarations (reused)
function logic [31:0] word_expan (input logic [31:0]w_arr[15:0]);
    logic [31:0] s0,s1;
    s0 = (rightrotate(w_arr[1], 7)) ^ (rightrotate(w_arr[1], 18)) ^ (rightshift(w_arr[1], 3));
    s1 = (rightrotate(w_arr[14], 17)) ^ (rightrotate(w_arr[14], 19)) ^ (rightshift(w_arr[14], 10));
    word_expan = w_arr[0] + s0 + w_arr[9] + s1;
endfunction

function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, k_val);
    logic [31:0] S1, S0, ch, maj, t1, t2;
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k_val + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
endfunction

function logic [31:0] rightrotate(input logic [31:0] x, input logic [7:0] r);
    rightrotate = (x >> r) | (x << (32 - r));
endfunction

function logic [31:0] rightshift(input logic [31:0] x, input logic [7:0] r);
    rightshift = (x >> r);
endfunction

// Memory interface logic
assign mem_clk = clk;
assign mem_addr = (state == READ) ? (message_addr + offset) : (output_addr + offset);
assign mem_we = (state == WRITE) ? 1'b1 : 1'b0;

// Prepare common message tail (Words 16, 17, 18) for Block 2
assign msg_tail[0] = message_buffer[16];
assign msg_tail[1] = message_buffer[17];
assign msg_tail[2] = message_buffer[18];

always_ff @(posedge clk, negedge reset_n) begin
    if (!reset_n) begin
        state <= IDLE;
        done <= 0;
        offset <= 0;
        i <= 0;
        tstep <= 0;
        // clear arrays (optional but safe)
        for (int n=0; n<num_nonce; n++) begin
            a[n] <= 0; b[n] <= 0; c[n] <= 0; d[n] <= 0;
            e[n] <= 0; f[n] <= 0; g[n] <= 0; h_reg[n] <= 0;
            for (int j=0; j<16; j++) wt[n][j] <= 0;
        end
        for (int j=0; j<16; j++) w[j] <= 0;
        group_sel <= 0;
    end else begin
        case (state)
            IDLE: begin
                done <= 0;
                if (start) begin
                    offset <= 0;
                    i <= 0;
                    state <= READ;
                end
            end

            READ: begin
                if (offset < 19) offset <= offset + 1;

                if (offset > 0 && i < 19) begin
                    message_buffer[i] <= mem_read_data;
                    i <= i + 1;
                end

                if (i == 19) begin
                    // prepare for Phase1
                    state <= PHASE1;
                    tstep <= 0;
                    {a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1} <=
                        {initial_hashes[0], initial_hashes[1], initial_hashes[2], initial_hashes[3],
                         initial_hashes[4], initial_hashes[5], initial_hashes[6], initial_hashes[7]};
                    // load first 16 words
                    for (int kk = 0; kk < 16; kk++) w[kk] <= message_buffer[kk];
                end
            end

            PHASE1: begin
                logic [31:0] current_w;
                if (tstep < 16) current_w = w[tstep];
                else current_w = word_expan(w);

                if (tstep < 64) begin
                    {a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1} <=
                        sha256_op(a_phase1, b_phase1, c_phase1, d_phase1, e_phase1, f_phase1, g_phase1, h_phase1, current_w, k[tstep]);
                    if (tstep >= 16) begin
                        for (int x=0; x<15; x++) w[x] <= w[x+1];
                        w[15] <= current_w;
                    end
                    tstep <= tstep + 1;
                end else begin
                    // phase1 done
                    phase1_hashes[0] <= a_phase1 + initial_hashes[0];
                    phase1_hashes[1] <= b_phase1 + initial_hashes[1];
                    phase1_hashes[2] <= c_phase1 + initial_hashes[2];
                    phase1_hashes[3] <= d_phase1 + initial_hashes[3];
                    phase1_hashes[4] <= e_phase1 + initial_hashes[4];
                    phase1_hashes[5] <= f_phase1 + initial_hashes[5];
                    phase1_hashes[6] <= g_phase1 + initial_hashes[6];
                    phase1_hashes[7] <= h_phase1 + initial_hashes[7];

                    // initialize per-nonce a..h to phase1 results + initial_hashes (as you intended)
                    for (int nn=0; nn<num_nonce; nn++) begin
                        a[nn] <= a_phase1 + initial_hashes[0];
                        b[nn] <= b_phase1 + initial_hashes[1];
                        c[nn] <= c_phase1 + initial_hashes[2];
                        d[nn] <= d_phase1 + initial_hashes[3];
                        e[nn] <= e_phase1 + initial_hashes[4];
                        f[nn] <= f_phase1 + initial_hashes[5];
                        g[nn] <= g_phase1 + initial_hashes[6];
                        h_reg[nn] <= h_phase1 + initial_hashes[7];
                        // clear their wt buffer initially
                        for (int x=0; x<16; x++) wt[nn][x] <= 0;
                    end

                    state <= PHASE2;
                    tstep <= 0;
                    group_sel <= 0;
                end
            end // PHASE1

            // ------------------------------
            // PHASE2: vectorized over all nonces (block 2)
            // ------------------------------
            PHASE2: begin
                // For each nonce n we compute its W_t (w_t) locally, update its wt buffer,
                // For each nonce n in the current group we compute its W_t (w_t) locally, update its wt buffer,
                // then perform sha256_op for that nonce using w_t and k[tstep].
                for (int n = 0; n < 8; n++) begin
                for (int k_idx = 0; k_idx < 8; k_idx++) begin
                    int n = k_idx + (group_sel ? 8 : 0);
                    // local combinational temp for this nonce & this round
                    logic [31:0] w_t;
                    // block2 message schedule
                    if (tstep < 3)            w_t = msg_tail[tstep];
                    else if (tstep == 3)      w_t = n;                // nonce (0..15)
                    else if (tstep == 4)      w_t = 32'h80000000;
                    else if (tstep < 15)      w_t = 32'h00000000;
                    else if (tstep == 15)     w_t = 32'd640;         // total bits length
                    else                      w_t = word_expan(wt[n]);

                    if (tstep < 64) begin
                        // update this nonce's wt buffer
                        if (tstep < 16) wt[n][tstep] <= w_t;
                        else begin
                            for (int x = 0; x < 15; x++) wt[n][x] <= wt[n][x+1];
                            wt[n][15] <= w_t;
                        end

                        // perform one sha256 round for this nonce
                        {a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n]} <=
                            sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n], w_t, k[tstep]);
                    end
                end // for n

                if (tstep < 64) tstep <= tstep + 1;
                else begin
                    // finalize block2 results: store intermediate H0..H7 into wt[n][0..7]
                    for (int n = 0; n < 8; n++) begin
                    for (int k_idx = 0; k_idx < 8; k_idx++) begin
                        int n = k_idx + (group_sel ? 8 : 0);
                        wt[n][0] <= a[n] + phase1_hashes[0];
                        wt[n][1] <= b[n] + phase1_hashes[1];
                        wt[n][2] <= c[n] + phase1_hashes[2];
                        wt[n][3] <= d[n] + phase1_hashes[3];
                        wt[n][4] <= e[n] + phase1_hashes[4];
                        wt[n][5] <= f[n] + phase1_hashes[5];
                        wt[n][6] <= g[n] + phase1_hashes[6];
                        wt[n][7] <= h_reg[n] + phase1_hashes[7];
                        // reset A..H to IV for phase3
                        a[n] <= initial_hashes[0];
                        b[n] <= initial_hashes[1];
                        c[n] <= initial_hashes[2];
                        d[n] <= initial_hashes[3];
                        e[n] <= initial_hashes[4];
                        f[n] <= initial_hashes[5];
                        g[n] <= initial_hashes[6];
                        h_reg[n] <= initial_hashes[7];
                    end
                    state <= PHASE2_P2;
                    tstep <= 0;
                end
            end // PHASE2
				
				PHASE2_P2: begin
                // For each nonce n we compute its W_t (w_t) locally, update its wt buffer,
                // then perform sha256_op for that nonce using w_t and k[tstep].
                for (int n = 8; n < num_nonce; n++) begin
                    // local combinational temp for this nonce & this round
                    logic [31:0] w_t;
                    // block2 message schedule
                    if (tstep < 3)            w_t = msg_tail[tstep];
                    else if (tstep == 3)      w_t = n;                // nonce (0..15)
                    else if (tstep == 4)      w_t = 32'h80000000;
                    else if (tstep < 15)      w_t = 32'h00000000;
                    else if (tstep == 15)     w_t = 32'd640;         // total bits length
                    else                      w_t = word_expan(wt[n]);

                    if (tstep < 64) begin
                        // update this nonce's wt buffer
                        if (tstep < 16) wt[n][tstep] <= w_t;
                        else begin
                            for (int x = 0; x < 15; x++) wt[n][x] <= wt[n][x+1];
                            wt[n][15] <= w_t;
                        end

                        // perform one sha256 round for this nonce
                        {a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n]} <=
                            sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n], w_t, k[tstep]);
                    
                    if (group_sel == 0) begin
                        group_sel <= 1;
                        tstep <= 0;
                    end else begin
                        group_sel <= 0;
                        state <= PHASE3;
                        tstep <= 0;
                    end
                end // for n

                if (tstep < 64) tstep <= tstep + 1;
                else begin
                    // finalize block2 results: store intermediate H0..H7 into wt[n][0..7]
                    for (int n = 8; n < num_nonce; n++) begin
                        wt[n][0] <= a[n] + phase1_hashes[0];
                        wt[n][1] <= b[n] + phase1_hashes[1];
                        wt[n][2] <= c[n] + phase1_hashes[2];
                        wt[n][3] <= d[n] + phase1_hashes[3];
                        wt[n][4] <= e[n] + phase1_hashes[4];
                        wt[n][5] <= f[n] + phase1_hashes[5];
                        wt[n][6] <= g[n] + phase1_hashes[6];
                        wt[n][7] <= h_reg[n] + phase1_hashes[7];
                        // reset A..H to IV for phase3
                        a[n] <= initial_hashes[0];
                        b[n] <= initial_hashes[1];
                        c[n] <= initial_hashes[2];
                        d[n] <= initial_hashes[3];
                        e[n] <= initial_hashes[4];
                        f[n] <= initial_hashes[5];
                        g[n] <= initial_hashes[6];
                        h_reg[n] <= initial_hashes[7];
                    end
                    state <= PHASE3;
                    tstep <= 0;
                end
            end // PHASE2

            // ------------------------------
            // PHASE3: vectorized over all nonces (block 3)
            // ------------------------------
            PHASE3: begin
                for (int n = 0; n < 8; n++) begin
                for (int k_idx = 0; k_idx < 8; k_idx++) begin
                    int n = k_idx + (group_sel ? 8 : 0);
                    logic [31:0] w_t;
                    // block3 message schedule using wt[n] produced from block2 finalization
                    if (tstep < 8)           w_t = wt[n][tstep];
                    else if (tstep == 8)     w_t = 32'h80000000;
                    else if (tstep < 15)     w_t = 32'h00000000;
                    else if (tstep == 15)    w_t = 32'd256; // 256 bits for single-block finalisation
                    else                     w_t = word_expan(wt[n]);

                    if (tstep < 64) begin
                        if (tstep < 16) wt[n][tstep] <= w_t;
                        else begin
                            for (int x = 0; x < 15; x++) wt[n][x] <= wt[n][x+1];
                            wt[n][15] <= w_t;
                        end

                        {a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n]} <=
                            sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n], w_t, k[tstep]);
                    end
                end // for n

                if (tstep < 64) tstep <= tstep + 1;
                else begin
                    for (int n = 0; n < 8; n++) begin
                    for (int k_idx = 0; k_idx < 8; k_idx++) begin
                        int n = k_idx + (group_sel ? 8 : 0);
                        // final H0 = IV[0] + a[n]  (user earlier expected H0 from final compression)
                        final_hashes[n] <= initial_hashes[0] + a[n];
                    end
                    state <= PHASE3_P2;
                    tstep <= 0;
                end
            end // PHASE3
				
				PHASE3_P2: begin
                for (int n = 8; n < num_nonce; n++) begin
                    logic [31:0] w_t;
                    // block3 message schedule using wt[n] produced from block2 finalization
                    if (tstep < 8)           w_t = wt[n][tstep];
                    else if (tstep == 8)     w_t = 32'h80000000;
                    else if (tstep < 15)     w_t = 32'h00000000;
                    else if (tstep == 15)    w_t = 32'd256; // 256 bits for single-block finalisation
                    else                     w_t = word_expan(wt[n]);

                    if (tstep < 64) begin
                        if (tstep < 16) wt[n][tstep] <= w_t;
                        else begin
                            for (int x = 0; x < 15; x++) wt[n][x] <= wt[n][x+1];
                            wt[n][15] <= w_t;
                        end

                        {a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n]} <=
                            sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h_reg[n], w_t, k[tstep]);
                    
                    if (group_sel == 0) begin
                        group_sel <= 1;
                        tstep <= 0;
                    end else begin
                        state <= WRITE;
                        tstep <= 0;
                        i <= 0;
                        offset <= 0;
                    end
                end // for n

                if (tstep < 64) tstep <= tstep + 1;
                else begin
                    for (int n = 8; n < num_nonce; n++) begin
                        // final H0 = IV[0] + a[n]  (user earlier expected H0 from final compression)
                        final_hashes[n] <= initial_hashes[0] + a[n];
                    end
                    state <= WRITE;
                    tstep <= 0;
                    i <= 0;
                    offset <= 0;
                end
            end // PHASE3

            WRITE: begin
                if (i < 16) begin
                    offset <= i;
                    mem_write_data <= final_hashes[i];
                    i <= i + 1;
                end else begin
                    done <= 1;
                    state <= IDLE;
                end
            end

            default: state <= IDLE;
        endcase
    end
end

endmodule
