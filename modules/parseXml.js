try { Object.defineProperty(Array.prototype, "peek", { value: function () { return (this.length > 0 ? this[this.length - 1] : undefined); } }); } catch (e) { }



function _treeBuilder()
{
    this.tree = [];

    this.push = function (element)
    {
        this.tree.push(element);
    };
    this.pop = function ()
    {
        var element = this.tree.pop();
        if(this.tree.length>0)
        {
            this.tree.peek().childNodes.push(element);
        }
        return (element);
    };
    this.peek = function()
    {
        return (this.tree.peek());
    }
    this.addNamespace = function(prefix, namespace)
    {
        this.tree.peek().nsTable[prefix] = namespace;
        if(this.tree.peek().attributes.length > 0)
        {
            for(var i = 0; i<this.tree.peek().attributes; ++i)
            {
                var a = this.tree.peek().attributes[i];
                if(prefix == '*' && a.name == a.localName)
                {
                    a.namespace = namespace;
                }
                else if(prefix != '*' && a.name != a.localName)
                {
                    var pfx = a.name.split(':')[0];
                    if(pfx == prefix)
                    {
                        a.namespace = namespace;
                    }
                }
            }
        }
    }
    this.getNamespace = function(prefix)
    {
        for(var i=this.tree.length-1;i>=0;--i)
        {
            if(this.tree[i].nsTable[prefix] != undefined)
            {
                return (this.tree[i].nsTable[prefix]);
            }
        }
        return ('undefined');
    }
}


// This is a drop-in replacement to _turnToXml() that works without xml parser dependency.
function _turnToXml(text)
{
    if (text == null) return null;
    return ({ childNodes: [_turnToXmlRec(text)], getElementsByTagName: _getElementsByTagName, getChildElementsByTagName: _getChildElementsByTagName, getElementsByTagNameNS: _getElementsByTagNameNS });
}

function _getElementsByTagNameNS(ns, name)
{
    var ret = []; _xmlTraverseAllRec(this.childNodes, function (node)
    {
        if (node.localName == name && (node.namespace == ns || ns == '*')) { ret.push(node); }
    }); return ret;
}
function _getElementsByTagName(name)
{
    var ret = []; _xmlTraverseAllRec(this.childNodes, function (node)
    {
        if (node.localName == name) { ret.push(node); }
    }); return ret;
}
function _getChildElementsByTagName(name)
{
    var ret = [];
    if (this.childNodes != undefined)
    {
        for (var node in this.childNodes) {
            if (this.childNodes[node].localName == name) { ret.push(this.childNodes[node]); }
        }
    }
    return (ret);
}
function _getChildElementsByTagNameNS(ns, name)
{
    var ret = [];
    if (this.childNodes != undefined)
    {
        for (var node in this.childNodes)
        {
            if (this.childNodes[node].localName == name && (ns == '*' || this.childNodes[node].namespace == ns)) { ret.push(this.childNodes[node]); }
        }
    }
    return (ret);
}

function _xmlTraverseAllRec(nodes, func) { for (var i in nodes) { func(nodes[i]); if (nodes[i].childNodes) { _xmlTraverseAllRec(nodes[i].childNodes, func); } } }
function _turnToXmlRec(text)
{
    var elementStack =  new _treeBuilder();
    var lastElement = null;

    var x1 = text.split('<'), ret = [], element = null, currentElementName = null;
    for (var i in x1)
    {
        var x2 = x1[i].split('>'), x3 = x2[0].split(' '), elementName = x3[0];
        if ((elementName.length > 0) && (elementName[0] != '?'))
        {
            if (elementName[0] != '/')
            {
                var localName;
                var localname2 = elementName.split(' ')[0].split(':'), localName = (localname2.length > 1) ? localname2[1] : localname2[0];
                var attributes = [];
                Object.defineProperty(attributes, "get",
                {
                    value: function ()
                    {
                        if (arguments.length == 1)
                        {
                            for (var a in this) { if (this[a].name == arguments[0]) { return (this[a]); } }
                        }
                        else if (arguments.length == 2)
                        {
                            for (var a in this) { if (this[a].name == arguments[1] && (arguments[0] == '*' || this[a].namespace == arguments[0])) { return (this[a]); } }
                        }
                        else
                        {
                            throw ('attributes.get(): Invalid number of parameters');
                        }
                    }
                });


                elementStack.push({ name: elementName, localName: localName, getChildElementsByTagName: _getChildElementsByTagName, getElementsByTagNameNS: _getElementsByTagNameNS, getChildElementsByTagNameNS: _getChildElementsByTagNameNS, attributes: attributes, childNodes: [], nsTable: {} });

                // Parse Attributes
                if (x3.length > 0)
                {
                    var skip = false;
                    for (var j in x3)
                    {
                        if (x3[j] == '/')  
                        {
                            // This is an empty Element
                            elementStack.peek().namespace = elementStack.peek().name == elementStack.peek().localName ? elementStack.getNamespace('*') : elementStack.getNamespace(elementStack.peek().name.substring(0, elementStack.peek().name.indexOf(':')));
                            elementStack.peek().textContent = '';
                            lastElement = elementStack.pop();
                            skip = true;
                            break;
                        }
                        var k = x3[j].indexOf('=');
                        if (k > 0)
                        {
                            var attrName = x3[j].substring(0, k);
                            var attrValue = x3[j].substring(k + 2, x3[j].length - 1);
                            var attrNS = elementStack.getNamespace('*');

                            if (attrName == 'xmlns')
                            {
                                elementStack.addNamespace('*', attrValue);
                                attrNS = attrValue;
                            }
                            else if (attrName.startsWith('xmlns:'))
                            {
                                elementStack.addNamespace(attrName.substring(6), attrValue);
                            }
                            else
                            {
                                var ax = attrName.split(':');
                                if (ax.length == 2) { attrName = ax[1]; attrNS = elementStack.getNamespace(ax[0]); }
                            }
                            elementStack.peek().attributes.push({ name: attrName, value: attrValue, namespace: attrNS });
                        }
                    }
                    if (skip) { continue; }
                }
                elementStack.peek().namespace = elementStack.peek().name == elementStack.peek().localName ? elementStack.getNamespace('*') : elementStack.getNamespace(elementStack.peek().name.substring(0, elementStack.peek().name.indexOf(':')));
                if (x2[1]) { elementStack.peek().textContent = x2[1]; }
            }
            else
            {
                lastElement = elementStack.pop();
            }                 
        }
    }
    return lastElement;
}

module.exports = _turnToXml;