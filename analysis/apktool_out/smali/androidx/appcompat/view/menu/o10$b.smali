.class public Landroidx/appcompat/view/menu/o10$b;
.super Landroidx/appcompat/view/menu/jd0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/o10;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "b"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/jd0;-><init>()V

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->j()Landroidx/appcompat/view/menu/iv0;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->D2()Landroidx/appcompat/view/menu/o3;

    move-result-object v1

    iget-object v1, v1, Landroidx/appcompat/view/menu/o3;->n:Ljava/lang/String;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/iv0;->g(Ljava/lang/String;)V

    invoke-virtual {p2, p1, p3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
