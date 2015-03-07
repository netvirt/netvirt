# -*- coding: utf-8 -*-

from jinja2 import FileSystemLoader, Environment

env = Environment(loader=FileSystemLoader('templates'), lstrip_blocks=True, trim_blocks=True)

for platform in ['debian', 'mac', 'mac-cli', 'windows', 'windows-cli']:
    template = env.get_template(platform + '.tpl')
    with open('build-%s.sh' % platform, 'w') as build_script:
        build_script.write(template.render())
