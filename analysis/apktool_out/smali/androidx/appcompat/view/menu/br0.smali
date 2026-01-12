.class public final Landroidx/appcompat/view/menu/br0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uq;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/zk0;

.field public final b:Landroidx/appcompat/view/menu/zk0;

.field public final c:Landroidx/appcompat/view/menu/zk0;

.field public final d:Landroidx/appcompat/view/menu/zk0;

.field public final e:Landroidx/appcompat/view/menu/zk0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/br0;->a:Landroidx/appcompat/view/menu/zk0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/br0;->b:Landroidx/appcompat/view/menu/zk0;

    iput-object p3, p0, Landroidx/appcompat/view/menu/br0;->c:Landroidx/appcompat/view/menu/zk0;

    iput-object p4, p0, Landroidx/appcompat/view/menu/br0;->d:Landroidx/appcompat/view/menu/zk0;

    iput-object p5, p0, Landroidx/appcompat/view/menu/br0;->e:Landroidx/appcompat/view/menu/zk0;

    return-void
.end method

.method public static a(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)Landroidx/appcompat/view/menu/br0;
    .locals 7

    new-instance v6, Landroidx/appcompat/view/menu/br0;

    move-object v0, v6

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/br0;-><init>(Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;Landroidx/appcompat/view/menu/zk0;)V

    return-object v6
.end method

.method public static c(Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/zk0;)Landroidx/appcompat/view/menu/ar0;
    .locals 7

    new-instance v6, Landroidx/appcompat/view/menu/ar0;

    move-object v3, p2

    check-cast v3, Landroidx/appcompat/view/menu/gp;

    move-object v4, p3

    check-cast v4, Landroidx/appcompat/view/menu/cs0;

    move-object v0, v6

    move-object v1, p0

    move-object v2, p1

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/ar0;-><init>(Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/gp;Landroidx/appcompat/view/menu/cs0;Landroidx/appcompat/view/menu/zk0;)V

    return-object v6
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/ar0;
    .locals 5

    iget-object v0, p0, Landroidx/appcompat/view/menu/br0;->a:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/dc;

    iget-object v1, p0, Landroidx/appcompat/view/menu/br0;->b:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v1}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/dc;

    iget-object v2, p0, Landroidx/appcompat/view/menu/br0;->c:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v2}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v2

    iget-object v3, p0, Landroidx/appcompat/view/menu/br0;->d:Landroidx/appcompat/view/menu/zk0;

    invoke-interface {v3}, Landroidx/appcompat/view/menu/zk0;->get()Ljava/lang/Object;

    move-result-object v3

    iget-object v4, p0, Landroidx/appcompat/view/menu/br0;->e:Landroidx/appcompat/view/menu/zk0;

    invoke-static {v0, v1, v2, v3, v4}, Landroidx/appcompat/view/menu/br0;->c(Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/zk0;)Landroidx/appcompat/view/menu/ar0;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic get()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/br0;->b()Landroidx/appcompat/view/menu/ar0;

    move-result-object v0

    return-object v0
.end method
