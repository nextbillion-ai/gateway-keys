set -e
docker_host=nextbillionai
docker_host_ar=asia-docker.pkg.dev/nextbillion/internal
image_name=gateway-keys

version=$CI_COMMIT_TAG
docker build -t $docker_host/$image_name:$version .
docker push $docker_host/$image_name:$version
docker tag $docker_host/$image_name:$version $docker_host_ar/$image_name:$version
docker push $docker_host_ar/$image_name:$version
exit 0
