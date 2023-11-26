/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.camel.converter;

import javax.jms.MessageListener;
import javax.jms.Message;
import javax.jms.TextMessage;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.test.junit4.CamelTestSupport;
import org.junit.Test;

/**
 * 
 */
public class InvokeJmsMessageListenerTest extends CamelTestSupport {
    protected MyMessageListener messageListener = new MyMessageListener();
    private String expectedBody = "<hello>world!</hello>";

    @Test
    public void testCamelInvokesMessageListener() throws Exception {
        template.sendBody("direct:start", expectedBody);

        Message message = messageListener.message;
        assertNotNull("Should have invoked the message listener!", message);
        TextMessage textMessage = assertIsInstanceOf(TextMessage.class, message);
        assertEquals("body", expectedBody, textMessage.getText());
    }

    @Override
    protected RouteBuilder createRouteBuilder() throws Exception {
        return new RouteBuilder() {
            public void configure() throws Exception {
                from("direct:start").bean(messageListener);
            }
        };
    }

    protected static class MyMessageListener implements MessageListener {
        public Message message;

        public void onMessage(Message message) {
            this.message = message;
        }
    }
}
