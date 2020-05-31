/*
Copyright 2018-2020 Intel Corporation

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

function powerMonitor()
{
    this._ObjectID = 'power-monitor';
    require('events').EventEmitter.call(this, true)
        .createEvent('changed')
        .createEvent('sx')
        .createEvent('batteryLevel')
        .createEvent('acdc')
        .createEvent('display');

    this._ACState = 1;
    this._BatteryLevel = -1;

    if (process.platform == 'win32')
    {
        // These must be registered BEFORE newListener is hooked up
        this.on('batteryLevel', function (level) { this._BatteryLevel = level; });
        this.on('acdc', function (m) { this._ACState = (m == 'AC' ? 1 : 0); });
    }

    this.on('newListener', function (name, callback)
    {
        if (name == 'acdc') { callback.call(this, this._ACState == 1 ? 'AC' : 'BATTERY'); }
        if (name == 'batteryLevel') { callback.call(this, this._BatteryLevel); }
    });

    this._i = setImmediate(function (self)
    {
        require('user-sessions'); // This is needed because this is where the Windows Messages are processed for these events
        delete self._i;
    }, this);

    if(process.platform == 'linux')
    {
        this._ACPath = null;
        this._BatteryPath = [];

        var devices = require('fs').readdirSync('/sys/class/power_supply');
        for (var i in devices)
        {
            if (require('fs').readFileSync('/sys/class/power_supply/' + devices[i] + '/type').toString().trim() == 'Mains')
            {
                this._ACPath = '/sys/class/power_supply/' + devices[i] + '/';
                break;
            }
        }
        for (var i in devices)
        {
            if (require('fs').readFileSync('/sys/class/power_supply/' + devices[i] + '/type').toString().trim() == 'Battery')
            {
                this._BatteryPath.push('/sys/class/power_supply/' + devices[i] + '/');
            }
        }
        if(this._ACPath != null)
        {
            this._ACState = parseInt(require('fs').readFileSync(this._ACPath + 'online').toString().trim());
        }
        if(this._BatteryPath.length>0)
        {
            this._getBatteryLevel = function _getBatteryLevel()
            {
                var sum = 0;
                var i;
                for (i in this._BatteryPath)
                {
                    sum += parseInt(require('fs').readFileSync(this._BatteryPath[i] + 'capacity').toString().trim());
                }
                sum = Math.floor(sum / this._BatteryPath.length);
                return (sum);
            }
            this._BatteryLevel = this._getBatteryLevel();
        }
        this._acpiSink = function _acpiSink(acpiEvent)
        {
            if(acpiEvent.name == 'ac_adapter')
            {
                _acpiSink.self._ACState = acpiEvent.value;
                _acpiSink.self.emit('acdc', acpiEvent.value == 1 ? 'AC' : 'BATTERY');
            }
        };
        this._acpiSink.self = this;
        require('linux-acpi').on('acpi', this._acpiSink);
    }
}

module.exports = new powerMonitor();