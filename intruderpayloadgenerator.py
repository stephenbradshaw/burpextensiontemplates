from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
from org.python.core.util import StringUtil
from java.io import PrintWriter


# Template for creating Jython Burp Suite Payload Generator Extensions for custom testing
# Changes go in MyPayloadGenerator and to constants directly below
# You probably wont need to change anything else

# Burp Extender API can be found online at: https://portswigger.net/burp/extender/api/


# Constants, change as required
GENERATOR_NAME = "My Generator"
EXTENSION_NAME = "My Extension"
LOAD_MESSAGE = "Extension loaded!"



############################################################################
# Shouldn't need to change this
############################################################################


class BurpExtender(IBurpExtender):
    '''BurpExtender Class to register the extension with Burp Suite'''

    def registerExtenderCallbacks(self, callbacks):
        '''Interface method to register the extender callbacks'''
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerIntruderPayloadGeneratorFactory(CustomPayloadGeneratorFactory(callbacks))
        stdout = PrintWriter(callbacks.getStdout(), True)
        stdout.println(LOAD_MESSAGE)


class CustomPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory):
    '''Custom Payload Generator Factory Class'''

    def __init__(self, callbacks):
        '''Override constructor so we can be passed Burp callbacks'''
        self.callbacks = callbacks

    def getGeneratorName(self):
        '''Interface method to return the generator name'''
        return GENERATOR_NAME


    def createNewInstance(self, attack):
        '''Interface method to create a new instance of the payload generator'''
        return MyPayloadGenerator(self.callbacks, attack)


class CustomPayloadGenerator(IIntruderPayloadGenerator):
    '''Custom Payload Generator Base Class'''


    def __init__(self, callbacks, attack, unicodePayload=False):
        self.callbacks = callbacks

        # use Unicode strings in Jython?
        self.unicodePayload = unicodePayload

        # this is all the stuff from attack so we dont need to store it
        httpService = attack.getHttpService()
        self.httpHost = httpService.getHost() # java.lang.String
        self.httpPort = httpService.getPort() # int
        self.httpProtocol = httpService.getProtocol() # java.lang.String
        self.requestTemplate = StringUtil.fromBytes(attack.getRequestTemplate()) # python unicode 
        if self.unicodePayload:
            self.self.requestTemplate = str(self.requestTemplate)

        self.morePayloads = True
        self.init()


    def init(self):
        '''Custom function to run when initialising or resetting the generator'''
        raise NotImplementedError


    def encode(self, value):
        '''Encoder method, run after payload processing and before payload is sent, returns str result'''
        #return str(value)
        raise NotImplementedError


    def decode(self, value):
        '''Decoder method, run before payload processing, returns str result'''
        #return str(value)
        raise NotImplementedError


    def process(self, value):
        '''Payload generation function, returns tuple (bool more_payloads, str result)'''
        #return (True, value + '!')
        raise NotImplementedError


    def reset(self):
        '''Interface method to reset payload state'''
        self.init()


    def hasMorePayloads(self):
        '''Interface method to determine if more payloads are available'''
        return self.morePayloads


    def getNextPayload(self, baseValue):
        '''Interface method to return the next generated payload'''
        strinput = StringUtil.fromBytes(baseValue)
        if not self.unicodePayload:
            strinput = str(strinput)
        bv = self.decode(strinput)
        (self.morePayloads, output) = self.process(bv)
        return self.encode(output)
 
 


############################################################################
# Stuff to change below here
############################################################################

# This example implementation will:
# * Decode the input parameter using URL safe base64 (web64)
# * Iterate each byte in the decoded value through each alternate byte value (255 of them)
# * Encode the processed value back into URL safe base64 (web64)


# This is an example working template, change it to do what you need


class MyPayloadGenerator(CustomPayloadGenerator):
    '''Edit me to create your custom payloads'''


    def __init__(self, callbacks, attack):
        '''
        Constructor, set up needed imports and object variables
        '''

        # Python unicode for extracted request values?
        self.unicodePayload = False 

        # call parent class __init__
        super(MyPayloadGenerator, self).__init__(callbacks, attack, unicodePayload=self.unicodePayload)


        # these custom to this example
        self.w64 = Web64()
        self.max_iteration = 255
        self.pos = 0
        self.iteration = 0    


    def init(self):
        '''
        State reset logic

        Have this perform steps to reset payload generator to the start position
        '''

        # example code
        self.pos = 0
        self.iteration = 0
        self.morePayloads = True


    def process(self, value):
        '''
        Payload generator code

        Generates the actual payload data, from the decoded input
        Will be passed through the encoder before being returned to Burp

        Returns a tuple:
        bool morePayloads   True if there are more
        str payloaddata     Processed payload data pre encoding
        '''

        # example code
        more = True
        self.iteration += 1
        munge = lambda x: chr((ord(x) + self.iteration) % 256)
        output = mungeByte(value, self.pos, munge)
        if self.iteration == self.max_iteration:
            self.iteration = 0
            self.pos += 1
        if self.pos == len(value):
            more = False
        return (more, output)


    def decode(self, value):
        '''
        Decoder

        Takes the input base value and decodes it for processing
        Have this return the input value if decoding is not needed

        Returns a single string:
        str value       The value after decoding

        '''
        return self.w64.decode(value)



    def encode(self, value):
        '''
        Encoder

        Takes the processed value and encodes it before passing to Burp
        Have this return the input value if encoding is not needed

        Returns a single string:
        str value       The value after decoding
        '''
        return self.w64.encode(value)



############################################################################
# Helper code for the example
############################################################################



def mungeByte(value, position, mungeFunction):
    '''Modifies a character in a given position in str value, using mungeFunction'''
    return value[0:position] + mungeFunction(value[position]) + value[position+1:]


class Web64(object):
    '''Web64 URL safe base64 encoder/decoder'''

    def __init__(self):
        from base64 import urlsafe_b64decode, urlsafe_b64encode
        self.dec = urlsafe_b64decode
        self.enc = urlsafe_b64encode


    def encode(self, value):
        '''Web64 encode'''
        return self.enc(value).replace('=', '')


    def decode(self, value):
        '''Web64 decode'''
        return self.dec(value + '=' *(3-(len(value)%3)))
