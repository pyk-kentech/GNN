'''
import argparse
import json
import os
import random
import re

from tqdm import tqdm
import networkx as nx
import pickle as pkl


node_type_dict = {}
edge_type_dict = {}
node_type_cnt = 0
edge_type_cnt = 0

metadata = {
    'trace':{
        'train': ['ta1-trace-e3-official-1.json', 'ta1-trace-e3-official-1.json.1', 'ta1-trace-e3-official-1.json.2', 'ta1-trace-e3-official-1.json.3'],
        'test': ['ta1-trace-e3-official-1.json', 'ta1-trace-e3-official-1.json.1', 'ta1-trace-e3-official-1.json.2', 'ta1-trace-e3-official-1.json.3', 'ta1-trace-e3-official-1.json.4']
    },
    'theia':{
            'train': ['ta1-theia-e3-official-6r.json', 'ta1-theia-e3-official-6r.json.1', 'ta1-theia-e3-official-6r.json.2', 'ta1-theia-e3-official-6r.json.3'],
            'test': ['ta1-theia-e3-official-6r.json.8']
    },
    'cadets':{
            'train': ['ta1-cadets-e3-official.json','ta1-cadets-e3-official.json.1', 'ta1-cadets-e3-official.json.2', 'ta1-cadets-e3-official-2.json.1'],
            'test': ['ta1-cadets-e3-official-2.json']
    }
}


pattern_uuid = re.compile(r'uuid\":\"(.*?)\"')
pattern_src = re.compile(r'subject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
pattern_dst1 = re.compile(r'predicateObject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
pattern_dst2 = re.compile(r'predicateObject2\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
pattern_type = re.compile(r'type\":\"(.*?)\"')
pattern_time = re.compile(r'timestampNanos\":(.*?),')
pattern_file_name = re.compile(r'map\":\{\"path\":\"(.*?)\"')
pattern_process_name = re.compile(r'map\":\{\"name\":\"(.*?)\"')
pattern_netflow_object_name = re.compile(r'remoteAddress\":\"(.*?)\"')


def read_single_graph(dataset, malicious, path, test=False):
    global node_type_cnt, edge_type_cnt
    g = nx.DiGraph()
    print('converting {} ...'.format(path))
    path = '../data/{}/'.format(dataset) + path + '.txt'
    f = open(path, 'r')
    lines = []
    for l in f.readlines():
        split_line = l.split('\t')
        src, src_type, dst, dst_type, edge_type, ts = split_line
        ts = int(ts)
        if not test:
            if src in malicious or dst in malicious:
                if src in malicious and src_type != 'MemoryObject':
                    continue
                if dst in malicious and dst_type != 'MemoryObject':
                    continue

        if src_type not in node_type_dict:
            node_type_dict[src_type] = node_type_cnt
            node_type_cnt += 1
        if dst_type not in node_type_dict:
            node_type_dict[dst_type] = node_type_cnt
            node_type_cnt += 1
        if edge_type not in edge_type_dict:
            edge_type_dict[edge_type] = edge_type_cnt
            edge_type_cnt += 1
        if 'READ' in edge_type or 'RECV' in edge_type or 'LOAD' in edge_type:
            lines.append([dst, src, dst_type, src_type, edge_type, ts])
        else:
            lines.append([src, dst, src_type, dst_type, edge_type, ts])
    lines.sort(key=lambda l: l[5])

    node_map = {}
    node_type_map = {}
    node_cnt = 0
    node_list = []
    for l in lines:
        src, dst, src_type, dst_type, edge_type = l[:5]
        src_type_id = node_type_dict[src_type]
        dst_type_id = node_type_dict[dst_type]
        edge_type_id = edge_type_dict[edge_type]
        if src not in node_map:
            node_map[src] = node_cnt
            g.add_node(node_cnt, type=src_type_id)
            node_list.append(src)
            node_type_map[src] = src_type
            node_cnt += 1
        if dst not in node_map:
            node_map[dst] = node_cnt
            g.add_node(node_cnt, type=dst_type_id)
            node_type_map[dst] = dst_type
            node_list.append(dst)
            node_cnt += 1
        if not g.has_edge(node_map[src], node_map[dst]):
            g.add_edge(node_map[src], node_map[dst], type=edge_type_id)
    return node_map, g


def preprocess_dataset(dataset):
    id_nodetype_map = {}
    id_nodename_map = {}
    for file in os.listdir('../data/{}/'.format(dataset)):
        if 'json' in file and not '.txt' in file and not 'names' in file and not 'types' in file and not 'metadata' in file:
            print('reading {} ...'.format(file))
            f = open('../data/{}/'.format(dataset) + file, 'r', encoding='utf-8')
            for line in tqdm(f):
                if 'com.bbn.tc.schema.avro.cdm18.Event' in line or 'com.bbn.tc.schema.avro.cdm18.Host' in line: continue
                if 'com.bbn.tc.schema.avro.cdm18.TimeMarker' in line or 'com.bbn.tc.schema.avro.cdm18.StartMarker' in line: continue
                if 'com.bbn.tc.schema.avro.cdm18.UnitDependency' in line or 'com.bbn.tc.schema.avro.cdm18.EndMarker' in line: continue
                if len(pattern_uuid.findall(line)) == 0: print(line)
                uuid = pattern_uuid.findall(line)[0]
                subject_type = pattern_type.findall(line)

                if len(subject_type) < 1:
                    if 'com.bbn.tc.schema.avro.cdm18.MemoryObject' in line:
                        subject_type = 'MemoryObject'
                    if 'com.bbn.tc.schema.avro.cdm18.NetFlowObject' in line:
                        subject_type = 'NetFlowObject'
                    if 'com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject' in line:
                        subject_type = 'UnnamedPipeObject'
                else:
                    subject_type = subject_type[0]

                if uuid == '00000000-0000-0000-0000-000000000000' or subject_type in ['SUBJECT_UNIT']:
                    continue
                id_nodetype_map[uuid] = subject_type
                if 'FILE' in subject_type and len(pattern_file_name.findall(line)) > 0:
                    id_nodename_map[uuid] = pattern_file_name.findall(line)[0]
                elif subject_type == 'SUBJECT_PROCESS' and len(pattern_process_name.findall(line)) > 0:
                    id_nodename_map[uuid] = pattern_process_name.findall(line)[0]
                elif subject_type == 'NetFlowObject' and len(pattern_netflow_object_name.findall(line)) > 0:
                    id_nodename_map[uuid] = pattern_netflow_object_name.findall(line)[0]
    for key in metadata[dataset]:
        for file in metadata[dataset][key]:
            if os.path.exists('../data/{}/'.format(dataset) + file + '.txt'):
                continue
            f = open('../data/{}/'.format(dataset) + file, 'r', encoding='utf-8')
            fw = open('../data/{}/'.format(dataset) + file + '.txt', 'w', encoding='utf-8')
            print('processing {} ...'.format(file))
            for line in tqdm(f):
                if 'com.bbn.tc.schema.avro.cdm18.Event' in line:
                    edgeType = pattern_type.findall(line)[0]
                    timestamp = pattern_time.findall(line)[0]
                    srcId = pattern_src.findall(line)

                    if len(srcId) == 0: continue
                    srcId = srcId[0]
                    if not srcId in id_nodetype_map:
                        continue
                    srcType = id_nodetype_map[srcId]
                    dstId1 = pattern_dst1.findall(line)
                    if len(dstId1) > 0 and dstId1[0] != 'null':
                        dstId1 = dstId1[0]
                        if not dstId1 in id_nodetype_map:
                            continue
                        dstType1 = id_nodetype_map[dstId1]
                        this_edge1 = str(srcId) + '\t' + str(srcType) + '\t' + str(dstId1) + '\t' + str(
                            dstType1) + '\t' + str(edgeType) + '\t' + str(timestamp) + '\n'
                        fw.write(this_edge1)

                    dstId2 = pattern_dst2.findall(line)
                    if len(dstId2) > 0 and dstId2[0] != 'null':
                        dstId2 = dstId2[0]
                        if not dstId2 in id_nodetype_map.keys():
                            continue
                        dstType2 = id_nodetype_map[dstId2]
                        this_edge2 = str(srcId) + '\t' + str(srcType) + '\t' + str(dstId2) + '\t' + str(
                            dstType2) + '\t' + str(edgeType) + '\t' + str(timestamp) + '\n'
                        fw.write(this_edge2)
            fw.close()
            f.close()
    if len(id_nodename_map) != 0:
        fw = open('../data/{}/'.format(dataset) + 'names.json', 'w', encoding='utf-8')
        json.dump(id_nodename_map, fw)
    if len(id_nodetype_map) != 0:
        fw = open('../data/{}/'.format(dataset) + 'types.json', 'w', encoding='utf-8')
        json.dump(id_nodetype_map, fw)


def read_graphs(dataset):
    malicious_entities = '../data/{}/{}.txt'.format(dataset, dataset)
    f = open(malicious_entities, 'r')
    malicious_entities = set()
    for l in f.readlines():
        malicious_entities.add(l.lstrip().rstrip())

    preprocess_dataset(dataset)
    train_gs = []
    for file in metadata[dataset]['train']:
        _, train_g = read_single_graph(dataset, malicious_entities, file, False)
        train_gs.append(train_g)
    test_gs = []
    test_node_map = {}
    count_node = 0
    for file in metadata[dataset]['test']:
        node_map, test_g = read_single_graph(dataset, malicious_entities, file, True)
        assert len(node_map) == test_g.number_of_nodes()
        test_gs.append(test_g)
        for key in node_map:
            if key not in test_node_map:
                test_node_map[key] = node_map[key] + count_node
        count_node += test_g.number_of_nodes()

    if os.path.exists('../data/{}/names.json'.format(dataset)) and os.path.exists('../data/{}/types.json'.format(dataset)):
        with open('../data/{}/names.json'.format(dataset), 'r', encoding='utf-8') as f:
            id_nodename_map = json.load(f)
        with open('../data/{}/types.json'.format(dataset), 'r', encoding='utf-8') as f:
            id_nodetype_map = json.load(f)
        f = open('../data/{}/malicious_names.txt'.format(dataset), 'w', encoding='utf-8')
        final_malicious_entities = []
        malicious_names = []
        for e in malicious_entities:
            if e in test_node_map and e in id_nodetype_map and id_nodetype_map[e] != 'MemoryObject' and id_nodetype_map[e] != 'UnnamedPipeObject':
                final_malicious_entities.append(test_node_map[e])
                if e in id_nodename_map:
                    malicious_names.append(id_nodename_map[e])
                    f.write('{}\t{}\n'.format(e, id_nodename_map[e]))
                else:
                    malicious_names.append(e)
                    f.write('{}\t{}\n'.format(e, e))
    else:
        f = open('../data/{}/malicious_names.txt'.format(dataset), 'w', encoding='utf-8')
        final_malicious_entities = []
        malicious_names = []
        for e in malicious_entities:
            if e in test_node_map:
                final_malicious_entities.append(test_node_map[e])
                malicious_names.append(e)
                f.write('{}\t{}\n'.format(e, e))

    pkl.dump((final_malicious_entities, malicious_names), open('../data/{}/malicious.pkl'.format(dataset), 'wb'))
    pkl.dump([nx.node_link_data(train_g) for train_g in train_gs], open('../data/{}/train.pkl'.format(dataset), 'wb'))
    pkl.dump([nx.node_link_data(test_g) for test_g in test_gs], open('../data/{}/test.pkl'.format(dataset), 'wb'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CDM Parser')
    parser.add_argument("--dataset", type=str, default="trace")
    args = parser.parse_args()
    if args.dataset not in ['trace', 'theia', 'cadets']:
        raise NotImplementedError
    read_graphs(args.dataset)

'''
import argparse
import json
import os
import re

from tqdm import tqdm
import networkx as nx
import pickle as pkl


# ------------------------------------------------------------
# Global type dicts
# ------------------------------------------------------------
node_type_dict = {}
edge_type_dict = {}
node_type_cnt = 0
edge_type_cnt = 0

# ------------------------------------------------------------
# Regex helpers: support both JSON text ("...") and escaped form (\")
# ------------------------------------------------------------
_Q = r'(?:\\"|")'   # matches either \" or "
_WS = r'\s*'

pattern_uuid = re.compile(rf'{_Q}uuid{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}')
pattern_time = re.compile(rf'{_Q}timestampNanos{_Q}{_WS}:{_WS}([0-9]+)')

# type can be: "type":"EVENT_OPEN"  OR  "type":{"string":"EVENT_OPEN"}
pattern_type_simple = re.compile(rf'{_Q}type{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}')
pattern_type_wrapped = re.compile(
    rf'{_Q}type{_Q}{_WS}:{_WS}\{{{_WS}{_Q}string{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}{_WS}\}}'
)

# subject / predicateObject / predicateObject2 are nested UUID records
pattern_src = re.compile(
    rf'{_Q}subject{_Q}{_WS}:{_WS}\{{{_WS}{_Q}com\.bbn\.tc\.schema\.avro\.cdm18\.UUID{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}{_WS}\}}'
)
pattern_dst1 = re.compile(
    rf'{_Q}predicateObject{_Q}{_WS}:{_WS}\{{{_WS}{_Q}com\.bbn\.tc\.schema\.avro\.cdm18\.UUID{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}{_WS}\}}'
)
pattern_dst2 = re.compile(
    rf'{_Q}predicateObject2{_Q}{_WS}:{_WS}\{{{_WS}{_Q}com\.bbn\.tc\.schema\.avro\.cdm18\.UUID{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}{_WS}\}}'
)

# Node name patterns (very tolerant: find "path":"..." / "name":"..." anywhere)
pattern_file_name = re.compile(rf'{_Q}path{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}')
pattern_process_name = re.compile(rf'{_Q}name{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}')
pattern_netflow_object_name = re.compile(rf'{_Q}remoteAddress{_Q}{_WS}:{_WS}{_Q}([^"\\]+){_Q}')


def _get_type(line: str):
    m = pattern_type_simple.search(line)
    if m:
        return m.group(1)
    m = pattern_type_wrapped.search(line)
    if m:
        return m.group(1)
    return None


def _get_uuid(line: str):
    m = pattern_uuid.search(line)
    return m.group(1) if m else None


def _get_time(line: str):
    m = pattern_time.search(line)
    return m.group(1) if m else None


def _get_first(m):
    return m.group(1) if m else None


def build_metadata_from_dir(dataset: str):
    """
    data/{dataset} 폴더에 실제 존재하는 ta1-*-e3-official*.json(.N) 파일만 모아서
    train/test 리스트를 자동 구성합니다.
    - 관례: train = first 4 parts, test = train + next 1 part
    - 파일이 적으면: 있는 만큼으로 구성
    """
    data_dir = f'../data/{dataset}/'  # utils/ 기준
    if not os.path.isdir(data_dir):
        raise FileNotFoundError(f'no such directory: {data_dir}')

    candidates = []
    for fn in os.listdir(data_dir):
        if not fn.endswith('.json') and '.json.' not in fn:
            continue
        if fn.endswith('.txt'):
            continue
        if fn in ('names.json', 'types.json', 'metadata.json'):
            continue
        if 'ta1-' in fn and '-e3-official' in fn and '.json' in fn:
            candidates.append(fn)

    if not candidates:
        raise FileNotFoundError(f'no ta1-*e3-official*.json files under {data_dir}')

    def part_key(name: str):
        # base: something.json / part: optional .N
        m = re.match(r'^(.*\.json)(?:\.(\d+))?$', name)
        if not m:
            return (name, 10**9)
        base = m.group(1)
        part = m.group(2)
        idx = int(part) if part is not None else 0
        return (base, idx)

    candidates.sort(key=part_key)

    grouped = {}
    for fn in candidates:
        base, idx = part_key(fn)
        grouped.setdefault(base, []).append((idx, fn))

    # pick the base that has the most parts
    best_base = max(grouped.keys(), key=lambda b: len(grouped[b]))
    parts = [fn for _, fn in sorted(grouped[best_base], key=lambda x: x[0])]

    train = parts[:4]
    test = parts[:5] if len(parts) >= 5 else parts[:]  # 없으면 있는 것만

    return {'train': train, 'test': test}


def preprocess_dataset(dataset: str, force_txt: bool = False):
    """
    1) uuid -> nodetype/nodename 맵 구축
    2) Event 라인에서 (src,dst,type,timestamp) 뽑아 *.txt(탭 구분 엣지 리스트) 생성
    """
    data_dir = f'../data/{dataset}/'
    runtime_meta = build_metadata_from_dir(dataset)

    id_nodetype_map = {}
    id_nodename_map = {}

    # ---------------------------
    # (A) 1st pass: build uuid -> nodetype/nodename maps
    # ---------------------------
    # NOTE: 어떤 json 조각에 엔티티 정의가 들어있을지 몰라서 "존재하는 모든 json"을 훑습니다.
    for file in os.listdir(data_dir):
        if ('json' not in file) or file.endswith('.txt'):
            continue
        if file in ('names.json', 'types.json', 'metadata.json'):
            continue

        path = os.path.join(data_dir, file)
        print(f'reading {file} ...')
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in tqdm(f):
                # UUID가 없는 marker/host/event 등은 안전하게 스킵
                if ('com.bbn.tc.schema.avro.cdm18.Event' in line) or ('com.bbn.tc.schema.avro.cdm18.Host' in line):
                    continue
                if ('com.bbn.tc.schema.avro.cdm18.TimeMarker' in line) or ('com.bbn.tc.schema.avro.cdm18.StartMarker' in line):
                    continue
                if ('com.bbn.tc.schema.avro.cdm18.UnitDependency' in line) or ('com.bbn.tc.schema.avro.cdm18.EndMarker' in line):
                    continue

                uuid = _get_uuid(line)
                if not uuid:
                    continue

                subject_type = _get_type(line)

                # fallback: some object records don't have "type"
                if not subject_type:
                    if 'com.bbn.tc.schema.avro.cdm18.MemoryObject' in line:
                        subject_type = 'MemoryObject'
                    elif 'com.bbn.tc.schema.avro.cdm18.NetFlowObject' in line:
                        subject_type = 'NetFlowObject'
                    elif 'com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject' in line:
                        subject_type = 'UnnamedPipeObject'
                    else:
                        continue

                if uuid == '00000000-0000-0000-0000-000000000000' or subject_type in ['SUBJECT_UNIT']:
                    continue

                id_nodetype_map[uuid] = subject_type

                # names
                if 'FILE' in subject_type:
                    m = pattern_file_name.search(line)
                    if m:
                        id_nodename_map[uuid] = m.group(1)
                elif subject_type == 'SUBJECT_PROCESS':
                    m = pattern_process_name.search(line)
                    if m:
                        id_nodename_map[uuid] = m.group(1)
                elif subject_type == 'NetFlowObject':
                    m = pattern_netflow_object_name.search(line)
                    if m:
                        id_nodename_map[uuid] = m.group(1)

    # ---------------------------
    # (B) 2nd pass: Event -> edges (*.txt)
    # ---------------------------
    for split in ('train', 'test'):
        for file in runtime_meta[split]:
            in_path = os.path.join(data_dir, file)
            out_path = os.path.join(data_dir, file + '.txt')

            if (not force_txt) and os.path.exists(out_path):
                continue

            print(f'processing {file} -> {os.path.basename(out_path)} ...')
            with open(in_path, 'r', encoding='utf-8', errors='replace') as f, \
                 open(out_path, 'w', encoding='utf-8') as fw:
                for line in tqdm(f):
                    if 'com.bbn.tc.schema.avro.cdm18.Event' not in line:
                        continue

                    edge_type = _get_type(line)
                    if not edge_type:
                        continue

                    timestamp = _get_time(line)
                    if not timestamp:
                        continue

                    src_id = _get_first(pattern_src.search(line))
                    if not src_id or src_id not in id_nodetype_map:
                        continue
                    src_type = id_nodetype_map[src_id]

                    dst1 = _get_first(pattern_dst1.search(line))
                    if dst1 and dst1 != 'null' and dst1 in id_nodetype_map:
                        fw.write(f"{src_id}\t{src_type}\t{dst1}\t{id_nodetype_map[dst1]}\t{edge_type}\t{timestamp}\n")

                    dst2 = _get_first(pattern_dst2.search(line))
                    if dst2 and dst2 != 'null' and dst2 in id_nodetype_map:
                        fw.write(f"{src_id}\t{src_type}\t{dst2}\t{id_nodetype_map[dst2]}\t{edge_type}\t{timestamp}\n")

    # dump maps
    print(f"[SANITY] types: {len(id_nodetype_map):,}  names: {len(id_nodename_map):,}")
    if id_nodename_map:
        with open(os.path.join(data_dir, 'names.json'), 'w', encoding='utf-8') as fw:
            json.dump(id_nodename_map, fw)
    if id_nodetype_map:
        with open(os.path.join(data_dir, 'types.json'), 'w', encoding='utf-8') as fw:
            json.dump(id_nodetype_map, fw)


def read_single_graph(dataset, malicious, file_basename, test=False):
    """
    file_basename: 'ta1-trace-e3-official-1.json' 또는 '...json.1' 같은 원본 파일명(확장자 포함)
    내부에서 '../data/{dataset}/{file_basename}.txt' 를 읽어 그래프 구성
    """
    global node_type_cnt, edge_type_cnt
    g = nx.DiGraph()
    data_dir = f'../data/{dataset}/'
    txt_path = os.path.join(data_dir, file_basename + '.txt')

    print(f'converting {os.path.basename(txt_path)} ...')

    lines = []
    with open(txt_path, 'r', encoding='utf-8', errors='replace') as f:
        for l in f:
            split_line = l.rstrip('\n').split('\t')
            if len(split_line) < 6:
                continue
            src, src_type, dst, dst_type, edge_type, ts = split_line
            try:
                ts = int(ts)
            except:
                continue

            if not test:
                if src in malicious or dst in malicious:
                    if src in malicious and src_type != 'MemoryObject':
                        continue
                    if dst in malicious and dst_type != 'MemoryObject':
                        continue

            if src_type not in node_type_dict:
                node_type_dict[src_type] = node_type_cnt
                node_type_cnt += 1
            if dst_type not in node_type_dict:
                node_type_dict[dst_type] = node_type_cnt
                node_type_cnt += 1
            if edge_type not in edge_type_dict:
                edge_type_dict[edge_type] = edge_type_cnt
                edge_type_cnt += 1

            # 방향 통일(READ/RECV/LOAD는 역방향)
            if ('READ' in edge_type) or ('RECV' in edge_type) or ('LOAD' in edge_type):
                lines.append([dst, src, dst_type, src_type, edge_type, ts])
            else:
                lines.append([src, dst, src_type, dst_type, edge_type, ts])

    lines.sort(key=lambda x: x[5])

    node_map = {}
    node_cnt = 0

    for src, dst, src_type, dst_type, edge_type, _ts in lines:
        src_type_id = node_type_dict[src_type]
        dst_type_id = node_type_dict[dst_type]
        edge_type_id = edge_type_dict[edge_type]

        if src not in node_map:
            node_map[src] = node_cnt
            g.add_node(node_cnt, type=src_type_id)
            node_cnt += 1
        if dst not in node_map:
            node_map[dst] = node_cnt
            g.add_node(node_cnt, type=dst_type_id)
            node_cnt += 1

        if not g.has_edge(node_map[src], node_map[dst]):
            g.add_edge(node_map[src], node_map[dst], type=edge_type_id)

    return node_map, g


def read_graphs(dataset: str, force_txt: bool = False):
    data_dir = f'../data/{dataset}/'
    runtime_meta = build_metadata_from_dir(dataset)

    # malicious entities list: ../data/{dataset}/{dataset}.txt
    malicious_path = os.path.join(data_dir, f'{dataset}.txt')
    if not os.path.exists(malicious_path):
        raise FileNotFoundError(f"malicious list not found: {malicious_path}")

    malicious_entities = set()
    with open(malicious_path, 'r', encoding='utf-8', errors='replace') as f:
        for l in f:
            l = l.strip()
            if l:
                malicious_entities.add(l)

    preprocess_dataset(dataset, force_txt=force_txt)

    train_gs = []
    for file in runtime_meta['train']:
        _, train_g = read_single_graph(dataset, malicious_entities, file, test=False)
        train_gs.append(train_g)

    test_gs = []
    test_node_map = {}
    count_node = 0

    for file in runtime_meta['test']:
        node_map, test_g = read_single_graph(dataset, malicious_entities, file, test=True)
        assert len(node_map) == test_g.number_of_nodes()
        test_gs.append(test_g)

        for key in node_map:
            if key not in test_node_map:
                test_node_map[key] = node_map[key] + count_node
        count_node += test_g.number_of_nodes()

    names_path = os.path.join(data_dir, 'names.json')
    types_path = os.path.join(data_dir, 'types.json')

    final_malicious_entities = []
    malicious_names = []

    if os.path.exists(names_path) and os.path.exists(types_path):
        with open(names_path, 'r', encoding='utf-8') as f:
            id_nodename_map = json.load(f)
        with open(types_path, 'r', encoding='utf-8') as f:
            id_nodetype_map = json.load(f)

        out_mal_names = os.path.join(data_dir, 'malicious_names.txt')
        with open(out_mal_names, 'w', encoding='utf-8') as fw:
            for e in malicious_entities:
                if e in test_node_map and e in id_nodetype_map and id_nodetype_map[e] not in ('MemoryObject', 'UnnamedPipeObject'):
                    final_malicious_entities.append(test_node_map[e])
                    if e in id_nodename_map:
                        malicious_names.append(id_nodename_map[e])
                        fw.write(f"{e}\t{id_nodename_map[e]}\n")
                    else:
                        malicious_names.append(e)
                        fw.write(f"{e}\t{e}\n")
    else:
        out_mal_names = os.path.join(data_dir, 'malicious_names.txt')
        with open(out_mal_names, 'w', encoding='utf-8') as fw:
            for e in malicious_entities:
                if e in test_node_map:
                    final_malicious_entities.append(test_node_map[e])
                    malicious_names.append(e)
                    fw.write(f"{e}\t{e}\n")

    pkl.dump((final_malicious_entities, malicious_names), open(os.path.join(data_dir, 'malicious.pkl'), 'wb'))
    pkl.dump([nx.node_link_data(g) for g in train_gs], open(os.path.join(data_dir, 'train.pkl'), 'wb'))
    pkl.dump([nx.node_link_data(g) for g in test_gs], open(os.path.join(data_dir, 'test.pkl'), 'wb'))

    print("[DONE]")
    print(f"  train graphs: {len(train_gs)}")
    print(f"  test graphs : {len(test_gs)}")
    print(f"  malicious entities in test-node-map: {len(final_malicious_entities)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CDM Parser (robust)')
    parser.add_argument("--dataset", type=str, default="trace")
    parser.add_argument("--force-txt", action="store_true", help="re-generate *.txt even if it exists")
    args = parser.parse_args()

    if args.dataset not in ['trace', 'theia', 'cadets']:
        raise NotImplementedError

    read_graphs(args.dataset, force_txt=args.force_txt)
