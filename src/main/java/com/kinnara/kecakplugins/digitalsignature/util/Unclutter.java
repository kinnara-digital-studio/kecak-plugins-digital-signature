package com.kinnara.kecakplugins.digitalsignature.util;

import org.joget.commons.util.LogUtil;
import org.json.JSONArray;
import org.json.JSONObject;
import org.kecak.apps.exception.ApiException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.text.html.Option;
import java.util.*;
import java.util.function.*;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * @@author aristo
 * <p>
 * Common library to handle repetition code
 */
public interface Unclutter {

    /**
     * Predicate not
     *
     * @param p
     * @param <T>
     * @return
     */
    default <T> Predicate<T> not(Predicate<T> p) {
        assert p != null;
        return t -> !p.test(t);
    }

    /**
     * Helper peek for {@link Optional}
     *
     * @param consumer
     * @param <T>
     * @return
     */
    @Nonnull
    default <T> UnaryOperator<T> peek(@Nonnull final Consumer<T> consumer) {
        return t -> {
            consumer.accept(t);
            return t;
        };
    }

    /**
     * Nullsafe. If string is null or empty
     *
     * @param value
     * @return
     */
    default boolean isEmpty(@Nullable Object value) {
        return Optional.ofNullable(value)
                .map(String::valueOf)
                .map(String::isEmpty)
                .orElse(true);
    }

    /**
     * Nullsafe. If object is not null and not empty
     *
     * @param value
     * @return
     */
    default boolean isNotEmpty(@Nullable Object value) {
        return !isEmpty(value);
    }

    /**
     * Nullsafe. If collection is null or empty
     *
     * @param collection
     * @param <T>
     * @return
     */
    default <T> boolean isEmpty(@Nullable Collection<T> collection) {
        return Optional.ofNullable(collection)
                .map(Collection::isEmpty)
                .orElse(true);
    }

    /**
     * Nullsafe. If collection is not null and not empty
     *
     * @param collection
     * @param <T>
     * @return
     */
    default <T> boolean isNotEmpty(@Nullable Collection<T> collection) {
        return !isEmpty(collection);
    }


    /**
     * If value null then return failover
     *
     * @param value
     * @param then
     * @param <T>
     * @return
     */
    @Nonnull
    default <T, U extends T> T ifNullThen(@Nullable T value, @Nonnull U then) {
        return value == null ? then : value;
    }

    /**
     * If value empty or null then return failover
     *
     * @param value
     * @param then
     * @param <T>
     * @return
     */
    default <T, U extends T> T ifEmptyThen(@Nullable T value, @Nonnull U then) {
        return isEmpty(value) ? then : value;
    }

    /**
     * Return null if string empty
     *
     * @param s
     * @return
     */
    default String nullIfEmpty(String s) {
        return s.isEmpty() ? null : s;
    }


    // JSON

    /**
     * Stream JSONArray
     *
     * @param jsonArray
     * @param <R>
     * @return
     */
    default <R> Stream<R> jsonStream(JSONArray jsonArray) {
        int length = Optional.ofNullable(jsonArray).map(JSONArray::length).orElse(0);
        return IntStream.iterate(0, i -> i + 1).limit(length)
                .boxed()
                .map(throwableFunction(jsonArray::get))
                .filter(Objects::nonNull)
                .map(throwableFunction(o -> (R) o))
                .filter(Objects::nonNull);
    }

    /**
     * Stream keys of JSONObject
     *
     * @param jsonObject
     * @return
     */
    default Stream<String> jsonStream(JSONObject jsonObject) {
        return Optional.ofNullable(jsonObject)
                .map(json -> StreamSupport.stream(Spliterators.spliteratorUnknownSize(
                        (Iterator<String>) json.keys(), 0), false))
                .orElseGet(Stream::empty);
    }

    // Throwable methods

    /**
     * @param throwableSupplier
     * @param <R>
     * @param <E>
     * @return
     */
    default <R, E extends Exception> ThrowableSupplier<R, E> throwableSupplier(ThrowableSupplier<R, E> throwableSupplier) {
        return throwableSupplier;
    }

    default <R, E extends Exception> ThrowableSupplier<R, E> throwableSupplier(ThrowableSupplier<R, E> throwableSupplier, Function<? super E, R> onException) {
        return throwableSupplier.onException(onException);
    }

    /**
     * @param throwableConsumer
     * @param <T>
     * @param <E>
     * @return
     */
    default <T, E extends Exception> ThrowableConsumer<T, ? super E> throwableConsumer(ThrowableConsumer<T, ? super E> throwableConsumer) {
        return throwableConsumer;
    }

    /**
     * @param throwableConsumer
     * @param failoverConsumer
     * @param <T>
     * @param <E>
     * @return
     */
    default <T, E extends Exception> Consumer<T> throwableConsumer(ThrowableConsumer<T, E> throwableConsumer, Consumer<? super E> failoverConsumer) {
        return throwableConsumer.onException(failoverConsumer);
    }

    /**
     * @param throwableBiConsumer
     * @param <T>
     * @param <U>
     * @param <E>
     * @return
     */
    default <T, U, E extends Exception> ThrowableBiConsumer<T, U, ? extends E> throwableBiConsumer(ThrowableBiConsumer<T, U, ? extends E> throwableBiConsumer) {
        return throwableBiConsumer;
    }

    /**
     * @param throwableFunction
     * @param <T>
     * @param <R>
     * @param <E>
     * @return
     */
    default <T, R, E extends Exception> ThrowableFunction<T, R, ? extends E> throwableFunction(ThrowableFunction<T, R, ? extends E> throwableFunction) {
        return throwableFunction;
    }

    /**
     * @param throwableFunction
     * @param failoverFunction
     * @param <T>
     * @param <R>
     * @param <E>
     * @return
     */
    default <T, R, E extends Exception> Function<T, R> throwableFunction(ThrowableFunction<T, R, E> throwableFunction, Function<? super E, ? extends R> failoverFunction) {
        return throwableFunction.onException(failoverFunction);
    }

    /**
     * @param throwableFunction
     * @param failoverFunction
     * @param <T>
     * @param <R>
     * @param <E>
     * @return
     */
    default <T, R, E extends Exception> Function<T, R> throwableFunction(ThrowableFunction<T, R, E> throwableFunction, BiFunction<T, E, R> failoverFunction) {
        return throwableFunction.onException(failoverFunction);
    }

    /**
     * @param throwablePredicate
     * @param <T>
     * @param <E>
     * @return
     */
    default <T, E extends Exception> Predicate<T> throwablePredicate(ThrowablePredicate<T, ? extends E> throwablePredicate) {
        return throwablePredicate;
    }

    // Extension for functional interfaces

    @FunctionalInterface
    interface ThrowableSupplier<R, E extends Exception> extends Supplier<R> {
        @Nullable
        R getThrowable() throws E;

        @Nullable
        default R get() {
            try {
                return getThrowable();
            } catch (Exception e) {
                LogUtil.error(getClass().getName(), e, e.getMessage());
                return null;
            }
        }

        default ThrowableSupplier<R, E> onException(Function<? super E, R> onException) {
            try {
                return this::getThrowable;
            } catch (Exception e) {
                Objects.requireNonNull(onException);
                return () -> onException.apply((E) e);
            }
        }
    }

    /**
     * Throwable version of {@link Function}.
     * Returns null then exception is raised
     *
     * @param <T>
     * @param <R>
     * @param <E>
     */
    @FunctionalInterface
    interface ThrowableFunction<T, R, E extends Exception> extends Function<T, R> {

        @Override
        default R apply(T t) {
            try {
                return applyThrowable(t);
            } catch (Exception e) {
                LogUtil.error(getClass().getName(), e, e.getMessage());
                return null;
            }
        }

        R applyThrowable(T t) throws E;

        /**
         * @param f
         * @return
         */
        default Function<T, R> onException(Function<? super E, ? extends R> f) {
            return (T a) -> {
                try {
                    return (R) applyThrowable(a);
                } catch (Exception e) {
                    return f.apply((E) e);
                }
            };
        }

        /**
         * @param f
         * @return
         */
        default Function<T, R> onException(BiFunction<? super T, ? super E, ? extends R> f) {
            return (T a) -> {
                try {
                    return (R) applyThrowable(a);
                } catch (Exception e) {
                    return f.apply(a, (E) e);
                }
            };
        }
    }

    /**
     * Throwable version of {@link Consumer}
     *
     * @param <T>
     * @param <E>
     */
    @FunctionalInterface
    interface ThrowableConsumer<T, E extends Exception> extends Consumer<T> {

        void acceptThrowable(T t) throws E;

        @Override
        default void accept(T t) {
            try {
                acceptThrowable(t);
            } catch (Exception e) {
                LogUtil.error(getClass().getName(), e, e.getMessage());
            }
        }

        default Consumer<T> onException(final Consumer<? super E> onException) {
            Objects.requireNonNull(onException);

            return (T t) -> {
                try {
                    acceptThrowable(t);
                } catch (Exception e) {
                    onException.accept((E) e);
                }
            };
        }
    }

    /**
     * Throwable version of {@link BiConsumer}
     *
     * @param <T>
     * @param <U>
     * @param <E>
     */
    @FunctionalInterface
    interface ThrowableBiConsumer<T, U, E extends Exception> extends BiConsumer<T, U> {
        void acceptThrowable(T t, U u) throws E;

        default void accept(T t, U u) {
            try {
                acceptThrowable(t, u);
            } catch (Exception e) {
                LogUtil.error(getClass().getName(), e, e.getMessage());
//                onException((E) e);
            }
        }

        default BiConsumer<T, U> onException(Consumer<? super E> consumer) {
            Objects.requireNonNull(consumer);

            return (T t, U u) -> {
                try {
                    acceptThrowable(t, u);
                } catch (Exception e) {
                    consumer.accept((E) e);
                }
            };

        }
    }

    /**
     * Throwable version of {@link Predicate}
     *
     * @param <T>
     * @param <E>
     */
    @FunctionalInterface
    interface ThrowablePredicate<T, E extends Exception> extends Predicate<T> {

        boolean testThrowable(T t) throws E;

        @Override
        default boolean test(T t) {
            try {
                return testThrowable(t);
            } catch (Exception e) {
                LogUtil.error(getClass().getName(), e, e.getMessage());
                return false;
            }
        }

        default Predicate<T> onException(Predicate<? super E> predicate) {
            return (T t) -> {
                try {
                    return testThrowable(t);
                } catch (Exception e) {
                    return predicate.test((E) e);
                }
            };
        }
    }

    default Optional<String> optParameter(HttpServletRequest request, String parameterName) {
        return Optional.of(parameterName).map(request::getParameter);
    }

    default String getParameter(HttpServletRequest request, String parameterName) throws ApiException {
        return optParameter(request, parameterName).orElseThrow(() -> new ApiException(HttpServletResponse.SC_BAD_REQUEST, "Parameter [" + parameterName + "] is required"));
    }
}
