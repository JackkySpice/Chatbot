.class public Landroidx/appcompat/view/menu/yk0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/t41;


# instance fields
.field public a:Z

.field public b:Z

.field public c:Landroidx/appcompat/view/menu/mr;

.field public final d:Landroidx/appcompat/view/menu/vk0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/vk0;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/yk0;->a:Z

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/yk0;->b:Z

    iput-object p1, p0, Landroidx/appcompat/view/menu/yk0;->d:Landroidx/appcompat/view/menu/vk0;

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/yk0;->a:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/yk0;->a:Z

    return-void

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/mo;

    const-string v1, "Cannot encode a second value in the ValueEncoderContext"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/mo;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public b(Landroidx/appcompat/view/menu/mr;Z)V
    .locals 1

    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/yk0;->a:Z

    iput-object p1, p0, Landroidx/appcompat/view/menu/yk0;->c:Landroidx/appcompat/view/menu/mr;

    iput-boolean p2, p0, Landroidx/appcompat/view/menu/yk0;->b:Z

    return-void
.end method

.method public c(Ljava/lang/String;)Landroidx/appcompat/view/menu/t41;
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yk0;->a()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/yk0;->d:Landroidx/appcompat/view/menu/vk0;

    iget-object v1, p0, Landroidx/appcompat/view/menu/yk0;->c:Landroidx/appcompat/view/menu/mr;

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/yk0;->b:Z

    invoke-virtual {v0, v1, p1, v2}, Landroidx/appcompat/view/menu/vk0;->g(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;Z)Landroidx/appcompat/view/menu/qf0;

    return-object p0
.end method

.method public d(Z)Landroidx/appcompat/view/menu/t41;
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yk0;->a()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/yk0;->d:Landroidx/appcompat/view/menu/vk0;

    iget-object v1, p0, Landroidx/appcompat/view/menu/yk0;->c:Landroidx/appcompat/view/menu/mr;

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/yk0;->b:Z

    invoke-virtual {v0, v1, p1, v2}, Landroidx/appcompat/view/menu/vk0;->l(Landroidx/appcompat/view/menu/mr;ZZ)Landroidx/appcompat/view/menu/vk0;

    return-object p0
.end method
