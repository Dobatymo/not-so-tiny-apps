(function() {
    const originalAttachShadow = Element.prototype.attachShadow;
    const nativeToString = Function.prototype.toString;

    const fakeAttachShadow = function(options) {
        console.log(options.mode, 'shadow attached to', this);
        const newOptions = Object.assign({}, options, {
            mode: 'open'
        });
        const shadow = originalAttachShadow.call(this, newOptions);

        Object.defineProperty(shadow, 'mode', {
            value: 'closed',
            writable: false,
            configurable: true,
            enumerable: true
        });

        return shadow;
    };

    Object.defineProperty(fakeAttachShadow, 'toString', {
        value: function() {
            return 'function attachShadow() { [native code] }';
        },
        writable: true,
        configurable: true,
    });

    Object.defineProperty(fakeAttachShadow.toString, 'toString', {
        value: function() {
            return 'function toString() { [native code] }';
        },
        writable: true,
        configurable: true,
    });

    Element.prototype.attachShadow = fakeAttachShadow


    Function.prototype.toString = new Proxy(nativeToString, {
        apply(target, thisArg, args) {
            // Case: Function.prototype.toString.call(Element.prototype.attachShadow.toString)
            if (thisArg === fakeAttachShadow.toString) {
                return 'function toString() { [native code] }';
            }

            // Case: Function.prototype.toString()
            if (thisArg === nativeToString) {
                return 'function attachShadow() { [native code] }';
            }

            // All other cases — fallback to original
            return Reflect.apply(target, thisArg, args);
        }
    });
})();

function checkAvailable() {
    const i = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'attachShadow'),
        s = 'function attachShadow() { [native code] }'.replace(/\s+/g, '') === Element.prototype.attachShadow.toString().replace(/\s+/g, ''),
        a = Function.prototype.toString.call(Function.prototype.toString).replace(/\s+/g, ''),
        d = 'function toString() { [native code] }'.replace(/\s+/g, ''),
        h = Function.prototype.toString.call(Element.prototype.attachShadow.toString).replace(/\s+/g, ''),
        e = h === a ||
        h === d,
        n = Function.prototype.toString() === 'function attachShadow() { [native code] }'.replace(/\s+/g, '');
    return !(i || !s || !(e && !n))
};

console.assert(document.createElement("div").attachShadow({
    'mode': 'closed'
}).mode === 'closed')
console.assert(checkAvailable());