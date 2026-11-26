package com.ureca.snac.support;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.IntFunction;

/**
 * 같은 시점에 출발선을 맞춘 뒤 요청을 동시에 실행하고 결과를 모은다.
 */
public final class ConcurrentExecutor {

    private ConcurrentExecutor() {
    }

    // 모든 요청이 출발선에 설 수 있도록 요청 수만큼 스레드를 만든다.
    public static <T> List<T> run(int requestCount, IntFunction<Callable<T>> taskFactory) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(requestCount);
        CountDownLatch ready = new CountDownLatch(requestCount);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < requestCount; i++) {
                Callable<T> task = taskFactory.apply(i);
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    return task.call();
                }));
            }
            ready.await();
            start.countDown();

            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get());
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }
}
