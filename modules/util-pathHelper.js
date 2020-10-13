/*
Copyright 2020 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

function makePath(path1, path2, useCWD)
{
    if (useCWD != null && useCWD)
    {
        var tokens = process.cwd().split(process.platform == 'win32' ? '\\' : '/');
        tokens.pop();
        tokens.push(path1.split(process.platform == 'win32' ? '\\' : '/').pop());
        path1 = tokens.join(process.platform == 'win32' ? '\\' : '/');
    }

    if (path2.startsWith('.'))
    {
        if (path1.toLowerCase().endsWith('.exe')) { path1 = path1.substring(0, path1.length - 4); }
        path1 += path2;
    }
    else
    {
        var tokens = path1.split(process.platform == 'win32' ? '\\' : '/');
        tokens.pop();
        tokens.push(path2);
        path1 = tokens.join(process.platform == 'win32' ? '\\' : '/');
    }
    return (path1);
}

module.exports = makePath;


