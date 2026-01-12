.class public final Landroidx/appcompat/view/menu/y60$a;
.super Landroidx/appcompat/view/menu/w60;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/y60;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field public final q:Landroidx/appcompat/view/menu/y60;

.field public final r:Landroidx/appcompat/view/menu/y60$b;

.field public final s:Landroidx/appcompat/view/menu/jb;

.field public final t:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y60;Landroidx/appcompat/view/menu/y60$b;Landroidx/appcompat/view/menu/jb;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/w60;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/y60$a;->q:Landroidx/appcompat/view/menu/y60;

    iput-object p2, p0, Landroidx/appcompat/view/menu/y60$a;->r:Landroidx/appcompat/view/menu/y60$b;

    iput-object p3, p0, Landroidx/appcompat/view/menu/y60$a;->s:Landroidx/appcompat/view/menu/jb;

    iput-object p4, p0, Landroidx/appcompat/view/menu/y60$a;->t:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/y60$a;->w(Ljava/lang/Throwable;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method

.method public w(Ljava/lang/Throwable;)V
    .locals 3

    iget-object p1, p0, Landroidx/appcompat/view/menu/y60$a;->q:Landroidx/appcompat/view/menu/y60;

    iget-object v0, p0, Landroidx/appcompat/view/menu/y60$a;->r:Landroidx/appcompat/view/menu/y60$b;

    iget-object v1, p0, Landroidx/appcompat/view/menu/y60$a;->s:Landroidx/appcompat/view/menu/jb;

    iget-object v2, p0, Landroidx/appcompat/view/menu/y60$a;->t:Ljava/lang/Object;

    invoke-static {p1, v0, v1, v2}, Landroidx/appcompat/view/menu/y60;->F(Landroidx/appcompat/view/menu/y60;Landroidx/appcompat/view/menu/y60$b;Landroidx/appcompat/view/menu/jb;Ljava/lang/Object;)V

    return-void
.end method
