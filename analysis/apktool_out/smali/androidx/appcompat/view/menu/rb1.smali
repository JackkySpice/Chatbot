.class public final Landroidx/appcompat/view/menu/rb1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Landroidx/appcompat/view/menu/q2;

.field public final b:Landroidx/appcompat/view/menu/lr;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/q2;Landroidx/appcompat/view/menu/lr;Landroidx/appcompat/view/menu/qb1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/rb1;->a:Landroidx/appcompat/view/menu/q2;

    iput-object p2, p0, Landroidx/appcompat/view/menu/rb1;->b:Landroidx/appcompat/view/menu/lr;

    return-void
.end method

.method public static bridge synthetic a(Landroidx/appcompat/view/menu/rb1;)Landroidx/appcompat/view/menu/lr;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/rb1;->b:Landroidx/appcompat/view/menu/lr;

    return-object p0
.end method

.method public static bridge synthetic b(Landroidx/appcompat/view/menu/rb1;)Landroidx/appcompat/view/menu/q2;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/rb1;->a:Landroidx/appcompat/view/menu/q2;

    return-object p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    instance-of v1, p1, Landroidx/appcompat/view/menu/rb1;

    if-eqz v1, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/rb1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/rb1;->a:Landroidx/appcompat/view/menu/q2;

    iget-object v2, p1, Landroidx/appcompat/view/menu/rb1;->a:Landroidx/appcompat/view/menu/q2;

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/sf0;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/rb1;->b:Landroidx/appcompat/view/menu/lr;

    iget-object p1, p1, Landroidx/appcompat/view/menu/rb1;->b:Landroidx/appcompat/view/menu/lr;

    invoke-static {v1, p1}, Landroidx/appcompat/view/menu/sf0;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    return v0
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/rb1;->a:Landroidx/appcompat/view/menu/q2;

    iget-object v1, p0, Landroidx/appcompat/view/menu/rb1;->b:Landroidx/appcompat/view/menu/lr;

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/sf0;->b([Ljava/lang/Object;)I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    invoke-static {p0}, Landroidx/appcompat/view/menu/sf0;->c(Ljava/lang/Object;)Landroidx/appcompat/view/menu/sf0$a;

    move-result-object v0

    const-string v1, "key"

    iget-object v2, p0, Landroidx/appcompat/view/menu/rb1;->a:Landroidx/appcompat/view/menu/q2;

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/sf0$a;->a(Ljava/lang/String;Ljava/lang/Object;)Landroidx/appcompat/view/menu/sf0$a;

    move-result-object v0

    const-string v1, "feature"

    iget-object v2, p0, Landroidx/appcompat/view/menu/rb1;->b:Landroidx/appcompat/view/menu/lr;

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/sf0$a;->a(Ljava/lang/String;Ljava/lang/Object;)Landroidx/appcompat/view/menu/sf0$a;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sf0$a;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
