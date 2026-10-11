module Authzn.Benchmarks.Program

open BenchmarkDotNet.Running

[<EntryPoint>]
let main args =
    BenchmarkSwitcher
        .FromAssembly(typeof<EngineBenchmarks.EvaluationBenchmarks>.Assembly)
        .Run(args)
    |> ignore
    0
