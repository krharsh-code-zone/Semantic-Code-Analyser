import json

def save_unix_array(i,chunks,labels,normal_array,chunks_location):
    '''
    formate:
    {
    code_no: for only C language
    chunks_locations: [address of each chunk]
    chunks: ['list of strings']
    labels: safe or not
    normal_array: normalized_ndarray
    }
    '''
    i = {
            'code_no': i,
            'chunks_locations': chunks_location,
            'chunks': chunks,
            'labels' : labels,
            'normal_array': normal_array
        }
    i["normal_array"] = i["normal_array"].tolist()

    with open(r"D:\college\sem6\Semantic Code Analyzer\data\intermidiate data\unixcoder_embedding.json", "a", encoding="utf-8") as f:
        f.write(json.dumps(i))
        f.write("\n")