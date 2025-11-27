/*
Copyright 2024 Intel Corporation
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

//
// Professional logging module with timestamps and log levels
//

function pad(num) {
    return num < 10 ? '0' + num : '' + num;
}

function getTimestamp() {
    var d = new Date();
    var year = d.getFullYear();
    var month = pad(d.getMonth() + 1);
    var day = pad(d.getDate());
    var hours = pad(d.getHours());
    var minutes = pad(d.getMinutes());
    var seconds = pad(d.getSeconds());

    return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
}

function log(level, message) {
    console.log('[' + getTimestamp() + '] ' + level + ': ' + message);
}

function info(message) {
    log('INFO', message);
}

function warn(message) {
    log('WARN', message);
}

function error(message) {
    log('ERROR', message);
}

module.exports = {
    info: info,
    warn: warn,
    error: error
};
