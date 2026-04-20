app = proc do |_env|
  [200, { 'content-type' => 'text/plain' }, ["Hello from rchab buildpacks test\n"]]
end

run app
