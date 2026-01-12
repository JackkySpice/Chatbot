.class public final Landroidx/appcompat/view/menu/bw$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/bw;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field public a:I

.field public b:Landroidx/appcompat/view/menu/ev;

.field public c:Z

.field public d:I

.field public e:I

.field public f:I

.field public g:I

.field public h:Landroidx/lifecycle/f$b;

.field public i:Landroidx/lifecycle/f$b;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(ILandroidx/appcompat/view/menu/ev;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Landroidx/appcompat/view/menu/bw$a;->a:I

    iput-object p2, p0, Landroidx/appcompat/view/menu/bw$a;->b:Landroidx/appcompat/view/menu/ev;

    const/4 p1, 0x0

    iput-boolean p1, p0, Landroidx/appcompat/view/menu/bw$a;->c:Z

    .line 3
    sget-object p1, Landroidx/lifecycle/f$b;->q:Landroidx/lifecycle/f$b;

    iput-object p1, p0, Landroidx/appcompat/view/menu/bw$a;->h:Landroidx/lifecycle/f$b;

    iput-object p1, p0, Landroidx/appcompat/view/menu/bw$a;->i:Landroidx/lifecycle/f$b;

    return-void
.end method

.method public constructor <init>(ILandroidx/appcompat/view/menu/ev;Z)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Landroidx/appcompat/view/menu/bw$a;->a:I

    iput-object p2, p0, Landroidx/appcompat/view/menu/bw$a;->b:Landroidx/appcompat/view/menu/ev;

    iput-boolean p3, p0, Landroidx/appcompat/view/menu/bw$a;->c:Z

    .line 5
    sget-object p1, Landroidx/lifecycle/f$b;->q:Landroidx/lifecycle/f$b;

    iput-object p1, p0, Landroidx/appcompat/view/menu/bw$a;->h:Landroidx/lifecycle/f$b;

    iput-object p1, p0, Landroidx/appcompat/view/menu/bw$a;->i:Landroidx/lifecycle/f$b;

    return-void
.end method
