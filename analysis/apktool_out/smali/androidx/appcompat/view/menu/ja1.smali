.class public final Landroidx/appcompat/view/menu/ja1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uq;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/zk0;

.field public final b:Landroidx/appcompat/view/menu/zk0;

.field public final c:Landroidx/appcompat/view/menu/zk0;

.field public final d:Landroidx/appcompat/view/menu/zk0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ja1;->a:Landroidx/appcompat/view/menu/zk0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ja1;->b:Landroidx/appcompat/view/menu/zk0;

    iput-object p3, p0, Landroidx/appcompat/view/menu/ja1;->c:Landroidx/appcompat/view/menu/zk0;

    iput-object p4, p0, Landroidx/appcompat/view/menu/ja1;->d:Landroidx/appcompat/view/menu/zk0;

    return-void
.end method

.method public static a(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)Landroidx/appcompat/view/menu/ja1;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/ja1;

    invoke-direct {v0, p0, p1, p2, p3}, Landroidx/appcompat/view/menu/ja1;-><init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V

    return-object v0
.end method

.method public static c(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Landroidx/appcompat/view/menu/ly0;)Landroidx/appcompat/view/menu/ia1;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/ia1;

    invoke-direct {v0, p0, p1, p2, p3}, Landroidx/appcompat/view/menu/ia1;-><init>(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Landroidx/appcompat/view/menu/ly0;)V

    return-object v0
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/ia1;
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/ja1;->a:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/concurrent/Executor;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ja1;->b:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v1}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/fp;

    iget-object v2, p0, Landroidx/appcompat/view/menu/ja1;->c:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v2}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/la1;

    iget-object v3, p0, Landroidx/appcompat/view/menu/ja1;->d:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v3}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/view/menu/ly0;

    invoke-static {v0, v1, v2, v3}, Landroidx/appcompat/view/menu/ja1;->c(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Landroidx/appcompat/view/menu/ly0;)Landroidx/appcompat/view/menu/ia1;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic get()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ja1;->b()Landroidx/appcompat/view/menu/ia1;

    move-result-object v0

    return-object v0
.end method
