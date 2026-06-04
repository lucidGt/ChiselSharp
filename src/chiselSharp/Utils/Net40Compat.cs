using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

#if NET40
namespace System.Runtime.CompilerServices
{
    public interface IAsyncStateMachine
    {
        void MoveNext();
        void SetStateMachine(IAsyncStateMachine stateMachine);
    }

    public interface INotifyCompletion
    {
        void OnCompleted(Action continuation);
    }

    public interface ICriticalNotifyCompletion : INotifyCompletion
    {
        void UnsafeOnCompleted(Action continuation);
    }

    [AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
    public sealed class AsyncStateMachineAttribute : Attribute
    {
        public AsyncStateMachineAttribute(Type stateMachineType)
        {
            StateMachineType = stateMachineType;
        }

        public Type StateMachineType { get; private set; }
    }

    public struct AsyncVoidMethodBuilder
    {
        public static AsyncVoidMethodBuilder Create()
        {
            return new AsyncVoidMethodBuilder();
        }

        public void Start<TStateMachine>(ref TStateMachine stateMachine)
            where TStateMachine : IAsyncStateMachine
        {
            stateMachine.MoveNext();
        }

        public void SetStateMachine(IAsyncStateMachine stateMachine) { }
        public void SetResult() { }

        public void SetException(Exception exception)
        {
            ThreadPool.QueueUserWorkItem(delegate { throw exception; });
        }

        public void AwaitOnCompleted<TAwaiter, TStateMachine>(
            ref TAwaiter awaiter, ref TStateMachine stateMachine)
            where TAwaiter : INotifyCompletion
            where TStateMachine : IAsyncStateMachine
        {
            IAsyncStateMachine boxed = stateMachine;
            awaiter.OnCompleted(boxed.MoveNext);
        }

        public void AwaitUnsafeOnCompleted<TAwaiter, TStateMachine>(
            ref TAwaiter awaiter, ref TStateMachine stateMachine)
            where TAwaiter : ICriticalNotifyCompletion
            where TStateMachine : IAsyncStateMachine
        {
            IAsyncStateMachine boxed = stateMachine;
            awaiter.UnsafeOnCompleted(boxed.MoveNext);
        }
    }

    public struct AsyncTaskMethodBuilder
    {
        private TaskCompletionSource<object> _tcs;

        public static AsyncTaskMethodBuilder Create()
        {
            var builder = new AsyncTaskMethodBuilder();
            builder._tcs = new TaskCompletionSource<object>();
            return builder;
        }

        public Task Task { get { return _tcs.Task; } }

        public void Start<TStateMachine>(ref TStateMachine stateMachine)
            where TStateMachine : IAsyncStateMachine
        {
            stateMachine.MoveNext();
        }

        public void SetStateMachine(IAsyncStateMachine stateMachine) { }
        public void SetResult() { _tcs.SetResult(null); }
        public void SetException(Exception exception) { _tcs.SetException(exception); }

        public void AwaitOnCompleted<TAwaiter, TStateMachine>(
            ref TAwaiter awaiter, ref TStateMachine stateMachine)
            where TAwaiter : INotifyCompletion
            where TStateMachine : IAsyncStateMachine
        {
            IAsyncStateMachine boxed = stateMachine;
            awaiter.OnCompleted(boxed.MoveNext);
        }

        public void AwaitUnsafeOnCompleted<TAwaiter, TStateMachine>(
            ref TAwaiter awaiter, ref TStateMachine stateMachine)
            where TAwaiter : ICriticalNotifyCompletion
            where TStateMachine : IAsyncStateMachine
        {
            IAsyncStateMachine boxed = stateMachine;
            awaiter.UnsafeOnCompleted(boxed.MoveNext);
        }
    }

    public struct AsyncTaskMethodBuilder<TResult>
    {
        private TaskCompletionSource<TResult> _tcs;

        public static AsyncTaskMethodBuilder<TResult> Create()
        {
            var builder = new AsyncTaskMethodBuilder<TResult>();
            builder._tcs = new TaskCompletionSource<TResult>();
            return builder;
        }

        public Task<TResult> Task { get { return _tcs.Task; } }

        public void Start<TStateMachine>(ref TStateMachine stateMachine)
            where TStateMachine : IAsyncStateMachine
        {
            stateMachine.MoveNext();
        }

        public void SetStateMachine(IAsyncStateMachine stateMachine) { }
        public void SetResult(TResult result) { _tcs.SetResult(result); }
        public void SetException(Exception exception) { _tcs.SetException(exception); }

        public void AwaitOnCompleted<TAwaiter, TStateMachine>(
            ref TAwaiter awaiter, ref TStateMachine stateMachine)
            where TAwaiter : INotifyCompletion
            where TStateMachine : IAsyncStateMachine
        {
            IAsyncStateMachine boxed = stateMachine;
            awaiter.OnCompleted(boxed.MoveNext);
        }

        public void AwaitUnsafeOnCompleted<TAwaiter, TStateMachine>(
            ref TAwaiter awaiter, ref TStateMachine stateMachine)
            where TAwaiter : ICriticalNotifyCompletion
            where TStateMachine : IAsyncStateMachine
        {
            IAsyncStateMachine boxed = stateMachine;
            awaiter.UnsafeOnCompleted(boxed.MoveNext);
        }
    }

    public struct TaskAwaiter : ICriticalNotifyCompletion
    {
        private readonly Task _task;

        public TaskAwaiter(Task task)
        {
            _task = task;
        }

        public bool IsCompleted { get { return _task.IsCompleted; } }

        public void GetResult()
        {
            try
            {
                _task.Wait();
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException;
            }
        }

        public void OnCompleted(Action continuation)
        {
            _task.ContinueWith(delegate { continuation(); });
        }

        public void UnsafeOnCompleted(Action continuation)
        {
            OnCompleted(continuation);
        }
    }

    public struct TaskAwaiter<TResult> : ICriticalNotifyCompletion
    {
        private readonly Task<TResult> _task;

        public TaskAwaiter(Task<TResult> task)
        {
            _task = task;
        }

        public bool IsCompleted { get { return _task.IsCompleted; } }

        public TResult GetResult()
        {
            try
            {
                return _task.Result;
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException;
            }
        }

        public void OnCompleted(Action continuation)
        {
            _task.ContinueWith(delegate { continuation(); });
        }

        public void UnsafeOnCompleted(Action continuation)
        {
            OnCompleted(continuation);
        }
    }
}

namespace System.Threading.Tasks
{
    public static class TaskAwaiterExtensions
    {
        public static System.Runtime.CompilerServices.TaskAwaiter GetAwaiter(this Task task)
        {
            return new System.Runtime.CompilerServices.TaskAwaiter(task);
        }

        public static System.Runtime.CompilerServices.TaskAwaiter<TResult> GetAwaiter<TResult>(this Task<TResult> task)
        {
            return new System.Runtime.CompilerServices.TaskAwaiter<TResult>(task);
        }
    }
}

namespace System.Threading
{
    public static class SemaphoreSlimExtensions
    {
        public static Task WaitAsync(this SemaphoreSlim semaphore)
        {
            if (semaphore.Wait(0))
                return ChiselSharp.Utils.Compat.FromResult<object>(null);
            return Task.Factory.StartNew(
                delegate { semaphore.Wait(); },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }
    }
}

namespace System.Net.Sockets
{
    public class UdpReceiveResult
    {
        public UdpReceiveResult(byte[] buffer, System.Net.IPEndPoint remoteEndPoint)
        {
            Buffer = buffer;
            RemoteEndPoint = remoteEndPoint;
        }

        public byte[] Buffer { get; private set; }
        public System.Net.IPEndPoint RemoteEndPoint { get; private set; }
    }

    public static class UdpClientExtensions
    {
        public static Task<UdpReceiveResult> ReceiveAsync(this UdpClient client)
        {
            return Task<UdpReceiveResult>.Factory.StartNew(delegate
            {
                System.Net.IPEndPoint remote = null;
                byte[] buffer = client.Receive(ref remote);
                return new UdpReceiveResult(buffer, remote);
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public static Task<int> SendAsync(this UdpClient client, byte[] datagram, int bytes, string hostname, int port)
        {
            return Task<int>.Factory.StartNew(delegate
            {
                return client.Send(datagram, bytes, hostname, port);
            }, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
        }
    }
}
#endif

namespace ChiselSharp.Utils
{
    public interface IAsyncCompatStream
    {
        Task<int> ReadAsyncCompat(byte[] buffer, int offset, int count, CancellationToken cancellationToken);
        Task WriteAsyncCompat(byte[] buffer, int offset, int count, CancellationToken cancellationToken);
        Task FlushAsyncCompat(CancellationToken cancellationToken);
    }

    public static class Compat
    {
        public static Task FromResult()
        {
            return FromResult<object>(null);
        }

        public static Task<TResult> FromResult<TResult>(TResult result)
        {
            var tcs = new TaskCompletionSource<TResult>();
            tcs.SetResult(result);
            return tcs.Task;
        }

        public static Task Run(Action action)
        {
            return Task.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
        }

        public static Task<TResult> Run<TResult>(Func<TResult> action)
        {
            return Task<TResult>.Factory.StartNew(action, CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
        }

        public static Task Run(Func<Task> action)
        {
            return RunTask(action, TaskCreationOptions.None);
        }

        public static Task RunLong(Func<Task> action)
        {
            return RunTask(action, TaskCreationOptions.LongRunning);
        }

        private static Task RunTask(Func<Task> action, TaskCreationOptions creationOptions)
        {
            var tcs = new TaskCompletionSource<object>();
            Task.Factory.StartNew(delegate
            {
                try
                {
                    Task inner = action();
                    inner.ContinueWith(delegate(Task completed)
                    {
                        if (completed.IsFaulted && completed.Exception != null)
                            tcs.TrySetException(completed.Exception.InnerExceptions);
                        else if (completed.IsCanceled)
                            tcs.TrySetCanceled();
                        else
                            tcs.TrySetResult(null);
                    }, TaskScheduler.Default);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }, CancellationToken.None, creationOptions, TaskScheduler.Default);
            return tcs.Task;
        }

        public static Task Delay(TimeSpan delay, CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<object>();
            Timer timer = null;
            timer = new Timer(delegate
            {
                timer.Dispose();
                tcs.TrySetResult(null);
            }, null, delay, TimeSpan.FromMilliseconds(-1));

            if (cancellationToken.CanBeCanceled)
            {
                cancellationToken.Register(delegate
                {
                    timer.Dispose();
                    tcs.TrySetCanceled();
                });
            }

            return tcs.Task;
        }

        public static Task Delay(int milliseconds)
        {
            return Delay(TimeSpan.FromMilliseconds(milliseconds), CancellationToken.None);
        }

        public static Task<Task> WhenAny(Task first, Task second)
        {
            var tcs = new TaskCompletionSource<Task>();
            first.ContinueWith(delegate { tcs.TrySetResult(first); });
            second.ContinueWith(delegate { tcs.TrySetResult(second); });
            return tcs.Task;
        }

        public static Task WhenAll(params Task[] tasks)
        {
            return Task.Factory.ContinueWhenAll(tasks, delegate(Task[] completed)
            {
                List<Exception> errors = null;
                foreach (Task task in completed)
                {
                    if (task.IsFaulted && task.Exception != null)
                    {
                        if (errors == null)
                            errors = new List<Exception>();
                        errors.AddRange(task.Exception.InnerExceptions);
                    }
                }
                if (errors != null)
                    throw new AggregateException(errors);
            });
        }

        public static Task<int> ReadAsync(this Stream stream, byte[] buffer, int offset, int count)
        {
            IAsyncCompatStream compat = stream as IAsyncCompatStream;
            if (compat != null)
                return compat.ReadAsyncCompat(buffer, offset, count, CancellationToken.None);

            return Task<int>.Factory.FromAsync(
                stream.BeginRead(buffer, offset, count, null, null),
                stream.EndRead);
        }

        public static Task<int> ReadAsync(this Stream stream, byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            IAsyncCompatStream compat = stream as IAsyncCompatStream;
            if (compat != null)
                return compat.ReadAsyncCompat(buffer, offset, count, cancellationToken);

            return ReadAsync(stream, buffer, offset, count);
        }

        public static Task WriteAsync(this Stream stream, byte[] buffer, int offset, int count)
        {
            IAsyncCompatStream compat = stream as IAsyncCompatStream;
            if (compat != null)
                return compat.WriteAsyncCompat(buffer, offset, count, CancellationToken.None);

            return Task.Factory.FromAsync(
                stream.BeginWrite(buffer, offset, count, null, null),
                stream.EndWrite);
        }

        public static Task WriteAsync(this Stream stream, byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            IAsyncCompatStream compat = stream as IAsyncCompatStream;
            if (compat != null)
                return compat.WriteAsyncCompat(buffer, offset, count, cancellationToken);

            return WriteAsync(stream, buffer, offset, count);
        }

        public static Task FlushAsync(this Stream stream)
        {
            IAsyncCompatStream compat = stream as IAsyncCompatStream;
            if (compat != null)
                return compat.FlushAsyncCompat(CancellationToken.None);

            stream.Flush();
            return FromResult();
        }

        public static Task FlushAsync(this Stream stream, CancellationToken cancellationToken)
        {
            IAsyncCompatStream compat = stream as IAsyncCompatStream;
            if (compat != null)
                return compat.FlushAsyncCompat(cancellationToken);

            return FlushAsync(stream);
        }

        public static Task<TcpClient> AcceptTcpClientAsync(TcpListener listener)
        {
            return Task<TcpClient>.Factory.FromAsync(listener.BeginAcceptTcpClient, listener.EndAcceptTcpClient, null);
        }

        public static Task ConnectTcpAsync(TcpClient client, string host, int port)
        {
            return Task.Factory.FromAsync(client.BeginConnect(host, port, null, null), client.EndConnect);
        }

        public static Task ConnectTcpAsync(TcpClient client, System.Net.IPAddress address, int port)
        {
            return Task.Factory.FromAsync(client.BeginConnect(address, port, null, null), client.EndConnect);
        }
    }
}
