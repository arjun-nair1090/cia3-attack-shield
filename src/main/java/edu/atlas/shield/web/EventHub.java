package edu.atlas.shield.web;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Fan-out of live events to every open dashboard over Server-Sent Events. */
@Component
public class EventHub {

    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public SseEmitter subscribe() {
        SseEmitter e = new SseEmitter(0L); // never time out; the browser reconnects on its own if dropped
        emitters.add(e);
        e.onCompletion(() -> emitters.remove(e));
        e.onTimeout(() -> emitters.remove(e));
        e.onError(x -> emitters.remove(e));
        return e;
    }

    public void publish(String name, Object data) {
        for (SseEmitter e : emitters) {
            try {
                e.send(SseEmitter.event().name(name).data(data));
            } catch (Exception gone) {
                emitters.remove(e);
            }
        }
    }
}
