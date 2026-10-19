import requests

print('=== 测试 Sympas MCP 新端点 ===')

endpoints = [
    ('/tools/execute/sympas_slice', {'source_file': 'test.c', 'variable': 'buffer'}),
    ('/tools/execute/sympas-hv', {'target_file': 'test.c'}),
    ('/tools/execute/start_scan', {'target_dir': '/tmp'}),
    ('/tools/execute/generate_mr', {'program_path': 'test.c', 'mr_count': 3}),
    ('/tools/execute/concurrency_check', {'source_dir': '/tmp'}),
    ('/tools/execute/dep_cluster', {'project_dir': '/tmp'}),
    ('/tools/execute/sympas_dep_graph', {'source_file': 'test.c'}),
    ('/tools/execute/taint_path_explainer', {'source_file': 'test.c'}),
    ('/tools/execute/reachability_query', {'target_symbol': 'main'}),
    ('/tools/execute/slice_diff', {'original_file': 'test.c', 'patched_file': 'test_patched.c'}),
]

success_count = 0
fail_count = 0

for endpoint, params in endpoints:
    try:
        r = requests.post('http://localhost:2266' + endpoint, json=params, timeout=10)
        status = r.status_code
        if status == 200:
            success_count += 1
            print(f'{endpoint}: {status} - OK')
        else:
            fail_count += 1
            print(f'{endpoint}: {status} - ERROR')
    except Exception as e:
        fail_count += 1
        print(f'{endpoint}: ERROR - {e}')

print(f'\n=== 测试结果: {success_count}个成功, {fail_count}个失败 ===')
