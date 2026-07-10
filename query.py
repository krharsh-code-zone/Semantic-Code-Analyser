import chromadb

def querring(normal_arrays):
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_collection(name="code_embeddings")

    results = collection.query(
        query_embeddings=normal_arrays,
        n_results=5
    )

    cleaned = []

    # each query result
    for q in range(len(results["ids"])):

        query_result = []
        
        for i in range(len(results["ids"][q])):
            query_result.append({
                "id": results["ids"][q][i],
                "document": results["documents"][q][i],
                "metadata": results["metadatas"][q][i],
                "distance": results["distances"][q][i],
            })

        cleaned.append(query_result)

    return cleaned

# [{'ids': [['552_0', '883_0', '330_0', '243_0', '833_0']],
#    'embeddings': None, 
#    'documents': [["// Context: // vuln: ['CWE-125 (Out-of-bounds Read)']// code: icmp6_opt_print(netdissect_options *ndo, const u_char *bp, int resid)", 
#                   "// Context: // vuln: ['safe']// code: dissect_u3v_event_cmd(proto_tree *u3v_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, gint startoffset, gint length)", 
#                   "// Context: // vuln: ['safe']// code: static int vp8_decode_frame_header(VP8Context *s, const uint8_t *buf, int buf_size)", 
#                   "// Context: // vuln: ['safe']// code: static int protocol_client_auth(VncState *vs, uint8_t *data, size_t len)", 
#                   "// Context: // vuln: ['safe']// code: static int read_normal_summaries(struct f2fs_sb_info *sbi, int type)"]],
#    'uris': None, 'included': ['metadatas', 'documents', 'distances'], 
#    'data': None, 
#    'metadatas': [[
#        {'end_byte': 69, 
#         'label': ['CWE-125 (Out-of-bounds Read)'], 
#         'start_byte': 0}, 
#         {'start_byte': 0, 
#          'label': ['safe'], 
#          'end_byte': 118}, 
#          {'end_byte': 83, 
#           'label': ['safe'], 
#           'start_byte': 0}, 
#           {'label': ['safe'], 
#            'end_byte': 72, 
#            'start_byte': 0}, 
#            {'label': ['safe'], 
#             'end_byte': 68, 
#             'start_byte': 0}
#             ]],
#    'distances': [[0.17067594826221466, 0.2969045341014862, 0.29937508702278137, 0.3036825954914093, 0.3187926411628723]]}]